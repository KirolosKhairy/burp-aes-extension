package burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Provides AES-aware insertion points to Burp Scanner.
 *
 * <p>For each actively scanned request whose host matches the configured target:
 * <ol>
 *   <li>Decrypts the AES-encrypted request body.</li>
 *   <li>Parses the plaintext (JSON or form-encoded) to find individual parameters.</li>
 *   <li>Returns one {@link AesInsertionPoint} per parameter so Burp can fuzz each value
 *       while the extension transparently re-encrypts payloads before sending.</li>
 * </ol>
 *
 * <p>JSON parsing handles:
 * <ul>
 *   <li>String values at any nesting depth: {@code "key":"value"}</li>
 *   <li>Numeric values: {@code "key":123} or {@code "key":-1.5}</li>
 *   <li>Boolean values: {@code "key":true} / {@code "key":false}</li>
 * </ul>
 *
 * <p>Implements {@link AuditInsertionPointProvider} (not the deprecated {@code ScanCheck}).
 * Registered via {@code api.scanner().registerInsertionPointProvider()}.
 */
public class AesScanCheck implements AuditInsertionPointProvider {

    private final BurpAesExtension extension;

    /** Matches JSON string values: {@code "key":"value"} (works at any nesting depth).
     *  The value group handles escaped quotes and backslashes via {@code (?:[^"\\]|\\.)*}. */
    private static final Pattern JSON_STRING =
            Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    /** Matches JSON numeric values: {@code "key":123} or {@code "key":-0.5}. */
    private static final Pattern JSON_NUMBER =
            Pattern.compile("\"([^\"]+)\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)");

    /** Matches JSON boolean values: {@code "key":true} or {@code "key":false}. */
    private static final Pattern JSON_BOOLEAN =
            Pattern.compile("\"([^\"]+)\"\\s*:\\s*(true|false)");

    /** Matches form-encoded parameters: {@code key=value} separated by {@code &}. */
    private static final Pattern FORM_PARAM =
            Pattern.compile("(?:^|(?<=&))([^=&]+)=([^&]*)");

    /**
     * @param extension the shared extension state (key, IV, target host)
     */
    public AesScanCheck(BurpAesExtension extension) {
        this.extension = extension;
    }

    /**
     * Decrypts the request body and extracts all fuzzable parameters as insertion points.
     *
     * @param baseHttpRequestResponse the base request/response being audited
     * @return a list of {@link AesInsertionPoint} objects, or {@code null} if not applicable
     */
    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse baseHttpRequestResponse) {
        String targetHost = extension.getTargetHost();
        if (targetHost == null || targetHost.isEmpty()) return null;

        try {
            String host = baseHttpRequestResponse.request().httpService().host();
            if (host == null || !host.contains(targetHost)) return null;
        } catch (Exception e) {
            return null;
        }

        String encryptedBody = baseHttpRequestResponse.request().bodyToString().trim();
        if (encryptedBody.isEmpty()) return null;

        String decryptedBody;
        try {
            byte[] plaintext = extension.getCryptoHelper().decrypt(encryptedBody);
            decryptedBody = new String(plaintext, StandardCharsets.UTF_8);
        } catch (Exception e) {
            extension.getLogging().logToError(
                    "AesScanCheck: decryption failed: " + e.getMessage());
            return null;
        }

        List<AuditInsertionPoint> points = new ArrayList<>();

        boolean looksLikeJson = decryptedBody.trim().startsWith("{")
                || decryptedBody.trim().startsWith("[");

        if (looksLikeJson) {
            extractJsonPoints(baseHttpRequestResponse, decryptedBody, points);
        } else if (decryptedBody.contains("=")) {
            extractFormPoints(baseHttpRequestResponse, decryptedBody, points);
        }

        return points.isEmpty() ? null : points;
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    /**
     * Extracts insertion points from a JSON body by matching string, numeric, and boolean
     * leaf values at any nesting depth. Each matched value's character offsets within
     * {@code body} are tracked for surgical payload substitution.
     *
     * @param reqResp the base request/response
     * @param body    the decrypted JSON body
     * @param points  the list to append new insertion points to
     */
    private void extractJsonPoints(HttpRequestResponse reqResp,
                                    String body,
                                    List<AuditInsertionPoint> points) {
        // String values — matched first to avoid numeric regex hitting inside strings
        Matcher strMatcher = JSON_STRING.matcher(body);
        while (strMatcher.find()) {
            String name = strMatcher.group(1);
            String value = strMatcher.group(2);
            points.add(new AesInsertionPoint(extension, reqResp.request(), body,
                    name, value, strMatcher.start(2), strMatcher.end(2)));
        }

        // Numeric values — skip positions already covered by string matches
        Matcher numMatcher = JSON_NUMBER.matcher(body);
        while (numMatcher.find()) {
            // Exclude positions that are inside a JSON string value matched above
            if (isInsideStringValue(body, numMatcher.start())) continue;
            String name  = numMatcher.group(1);
            String value = numMatcher.group(2);
            points.add(new AesInsertionPoint(extension, reqResp.request(), body,
                    name, value, numMatcher.start(2), numMatcher.end(2)));
        }

        // Boolean values — same exclusion
        Matcher boolMatcher = JSON_BOOLEAN.matcher(body);
        while (boolMatcher.find()) {
            if (isInsideStringValue(body, boolMatcher.start())) continue;
            String name  = boolMatcher.group(1);
            String value = boolMatcher.group(2);
            points.add(new AesInsertionPoint(extension, reqResp.request(), body,
                    name, value, boolMatcher.start(2), boolMatcher.end(2)));
        }
    }

    /**
     * Returns {@code true} if the character at {@code pos} in {@code body} is inside
     * a JSON string (key or value).
     *
     * <p>Scans forward from the start of {@code body}, tracking string state:
     * <ul>
     *   <li>An unescaped {@code "} toggles in/out of a string.</li>
     *   <li>A backslash skips the following character (escape sequence).</li>
     * </ul>
     * This correctly handles any ordering of field types and strings containing
     * colons, digits, {@code true}/{@code false}, or escaped quotes.
     *
     * @param body the JSON string
     * @param pos  the position to test
     * @return {@code true} if {@code pos} is inside a JSON string
     */
    private static boolean isInsideStringValue(String body, int pos) {
        boolean inString = false;
        for (int i = 0; i < pos && i < body.length(); i++) {
            char c = body.charAt(i);
            if (c == '\\' && inString) {
                i++; // skip escaped character
            } else if (c == '"') {
                inString = !inString;
            }
        }
        return inString;
    }

    /**
     * Extracts insertion points from a form-encoded body ({@code key=value&key2=value2}).
     *
     * @param reqResp the base request/response
     * @param body    the decrypted form-encoded body
     * @param points  the list to append new insertion points to
     */
    private void extractFormPoints(HttpRequestResponse reqResp,
                                    String body,
                                    List<AuditInsertionPoint> points) {
        Matcher m = FORM_PARAM.matcher(body);
        while (m.find()) {
            String name  = m.group(1);
            String value = m.group(2);
            points.add(new AesInsertionPoint(extension, reqResp.request(), body,
                    name, value, m.start(2), m.end(2)));
        }
    }
}
