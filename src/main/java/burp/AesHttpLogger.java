package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HTTP handler that intercepts every request and response passing through Burp.
 *
 * <p>For messages whose host matches the configured target host:
 * <ul>
 *   <li>Attempts to decrypt the body using {@link CryptoHelper}.</li>
 *   <li>Logs a one-line plaintext summary (first 100 chars) to Burp's output tab.</li>
 *   <li>Applies a CYAN row highlight so matched traffic is instantly visible in HTTP History.</li>
 * </ul>
 *
 * <p>Messages that cannot be decrypted (wrong key, not AES-encrypted, empty body) are
 * passed through silently without modification.
 */
public class AesHttpLogger implements HttpHandler {

    private static final int    PREVIEW_LEN = 100;
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final Pattern JSON_STRING =
            Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern FORM_PARAM =
            Pattern.compile("(?:^|(?<=&))([^=&]+)=([^&]*)");

    private final BurpAesExtension extension;
    private final MontoyaApi       api;

    /**
     * @param extension the shared extension state (key, IV, target host)
     * @param api       the Montoya API reference for logging
     */
    public AesHttpLogger(BurpAesExtension extension, MontoyaApi api) {
        this.extension = extension;
        this.api       = api;
    }

    /**
     * Intercepts outbound requests. If the host matches the target, ensures any
     * non-empty body is AES-encrypted before it leaves Burp.
     *
     * @param request information about the request about to be sent
     * @return a {@link RequestToBeSentAction} — always CONTINUE
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        String host;
        try {
            host = request.httpService().host();
        } catch (Exception e) {
            return RequestToBeSentAction.continueWith(request);
        }

        api.logging().logToOutput("AesHttpLogger: checking request to " + host);

        if (!hostMatches(host)) {
            return RequestToBeSentAction.continueWith(request);
        }

        HttpRequest outboundRequest = stripScannerMarkerHeader(request);
        String body = outboundRequest.bodyToString();
        if (body.isEmpty()) {
            return RequestToBeSentAction.continueWith(outboundRequest);
        }

        try {
            byte[] plaintext = extension.getCryptoHelper().decrypt(body);
            api.logging().logToOutput("AesHttpLogger: body is already encrypted, passing through");
            return continueWithLoggedRequest(
                    request,
                    outboundRequest,
                    new String(plaintext, StandardCharsets.UTF_8));

        } catch (Exception e) {
            if (isScannerRequest(request)) {
                HttpRequest repairedRequest = repairScannerRequest(outboundRequest, body.trim());
                if (repairedRequest != null) {
                    try {
                        String repairedPlaintext = new String(
                                extension.getCryptoHelper().decrypt(repairedRequest.bodyToString().trim()),
                                StandardCharsets.UTF_8);
                        return continueWithLoggedRequest(request, repairedRequest, repairedPlaintext);
                    } catch (Exception repairFailure) {
                        extension.getLogging().logToError(
                                "AesHttpLogger: repaired scanner request is still not decryptable: "
                                        + repairFailure.getMessage());
                        return RequestToBeSentAction.continueWith(repairedRequest);
                    }
                }
            }

            api.logging().logToOutput("AesHttpLogger: body is plaintext, encrypting...");
            try {
                String encryptedBody = extension.getCryptoHelper().encrypt(
                        body.getBytes(StandardCharsets.UTF_8));
                HttpRequest encryptedRequest = outboundRequest.withBody(encryptedBody);
                api.logging().logToOutput("AesHttpLogger: encryption successful, body replaced");
                return continueWithLoggedRequest(
                        request,
                        encryptedRequest,
                        body,
                        "Auto-encrypted by AES Traffic Decryptor");
            } catch (Exception encryptionFailure) {
                api.logging().logToOutput("AesHttpLogger: encryption failed, sending unencrypted");
                return RequestToBeSentAction.continueWith(outboundRequest);
            }
        }
    }

    /**
     * Intercepts inbound responses. If the host matches the target and the body is
     * AES-decryptable, logs a plaintext summary and marks the row CYAN.
     *
     * @param response information about the response that was received
     * @return a {@link ResponseReceivedAction} — always CONTINUE, never modifies the body
     */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            if (!hostMatches(response.initiatingRequest().httpService().host())) {
                return ResponseReceivedAction.continueWith(response);
            }
        } catch (Exception e) {
            return ResponseReceivedAction.continueWith(response);
        }

        String body = response.bodyToString().trim();
        if (body.isEmpty()) {
            return ResponseReceivedAction.continueWith(response);
        }

        try {
            byte[] plaintext = extension.getCryptoHelper().decrypt(body);
            String preview   = preview(new String(plaintext, StandardCharsets.UTF_8));
            String time      = LocalTime.now().format(TIME_FMT);

            api.logging().logToOutput(
                    "[" + time + "] RESPONSE "
                    + response.statusCode()
                    + "  |  Decrypted: " + preview);

            Annotations annotations = Annotations.annotations(HighlightColor.CYAN);
            return ResponseReceivedAction.continueWith(response, annotations);

        } catch (Exception e) {
            // Body is not AES-encrypted with the current key — pass through silently
            return ResponseReceivedAction.continueWith(response);
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    /**
     * Returns {@code true} if the given host contains the configured target host string.
     *
     * @param host the hostname from the HTTP service
     * @return {@code true} if it matches the target
     */
    private boolean hostMatches(String host) {
        String target = extension.getTargetHost();
        return target != null && !target.isEmpty()
                && host != null
                && host.toLowerCase(Locale.ROOT).contains(target.toLowerCase(Locale.ROOT));
    }

    private boolean isScannerRequest(HttpRequestToBeSent request) {
        try {
            return request.toolSource() != null && request.toolSource().isFromTool(ToolType.SCANNER);
        } catch (Exception e) {
            return false;
        }
    }

    private HttpRequest stripScannerMarkerHeader(HttpRequest request) {
        if (request.hasHeader(AesInsertionPoint.SCANNER_MARKER_HEADER)) {
            return request.withRemovedHeader(AesInsertionPoint.SCANNER_MARKER_HEADER);
        }
        return request;
    }

    private RequestToBeSentAction continueWithLoggedRequest(HttpRequestToBeSent originalRequest,
                                                            HttpRequest outboundRequest,
                                                            String decryptedBody) {
        return continueWithLoggedRequest(originalRequest, outboundRequest, decryptedBody, null);
    }

    private RequestToBeSentAction continueWithLoggedRequest(HttpRequestToBeSent originalRequest,
                                                            HttpRequest outboundRequest,
                                                            String decryptedBody,
                                                            String notes) {
        String time = LocalTime.now().format(TIME_FMT);

        api.logging().logToOutput(
                "[" + time + "] REQUEST  "
                        + originalRequest.method() + " " + safeUrl(originalRequest)
                        + "  |  Decrypted: " + preview(decryptedBody));

        Annotations annotations = Annotations.annotations(HighlightColor.CYAN);
        if (notes != null && !notes.isEmpty()) {
            annotations = annotations.withNotes(notes);
        }
        return RequestToBeSentAction.continueWith(outboundRequest, annotations);
    }

    private RequestToBeSentAction encryptPlaintextRequest(HttpRequestToBeSent originalRequest,
                                                          HttpRequest outboundRequest,
                                                          String plaintextBody) {
        try {
            String encryptedBody = extension.getCryptoHelper().encrypt(
                    plaintextBody.getBytes(StandardCharsets.UTF_8));
            return continueWithLoggedRequest(
                    originalRequest,
                    outboundRequest.withBody(encryptedBody),
                    plaintextBody);
        } catch (Exception e) {
            api.logging().logToOutput("Warning: Could not encrypt request body, sending unencrypted");
            return RequestToBeSentAction.continueWith(outboundRequest);
        }
    }

    private HttpRequest repairScannerRequest(HttpRequest outboundRequest, String corruptedBody) {
        BurpAesExtension.ScanRequestContext context = extension.scanRequestContextFor(outboundRequest);
        if (context == null || context.encryptedBody() == null || context.encryptedBody().isEmpty()) {
            return null;
        }

        if (!looksLikeCiphertextMutation(context.encryptedBody(), corruptedBody)) {
            return null;
        }

        if (context.encryptedBody().equals(corruptedBody)) {
            return outboundRequest.withBody(context.encryptedBody());
        }

        String originalPlaintext = context.decryptedBody();
        if (originalPlaintext == null) {
            return outboundRequest.withBody(context.encryptedBody());
        }

        String payload = extractInjectedPayload(context.encryptedBody(), corruptedBody);
        if (payload.isEmpty()) {
            api.logging().logToOutput(
                    "AesHttpLogger: restoring original encrypted scanner body after Burp corrupted Base64.");
            return outboundRequest.withBody(context.encryptedBody());
        }

        String repairedPlaintext = injectPayloadIntoPlaintext(originalPlaintext, payload);
        try {
            String repairedEncrypted = extension.getCryptoHelper().encrypt(
                    repairedPlaintext.getBytes(StandardCharsets.UTF_8));
            api.logging().logToOutput(
                    "AesHttpLogger: repaired scanner request body by moving payload from ciphertext to plaintext.");
            return outboundRequest.withBody(repairedEncrypted);
        } catch (Exception e) {
            extension.getLogging().logToError(
                    "AesHttpLogger: scanner request repair failed, restoring original body: "
                            + e.getMessage());
            return outboundRequest.withBody(context.encryptedBody());
        }
    }

    private static String extractInjectedPayload(String originalBody, String modifiedBody) {
        if (originalBody == null || modifiedBody == null || originalBody.equals(modifiedBody)) {
            return "";
        }

        int prefix = 0;
        int prefixLimit = Math.min(originalBody.length(), modifiedBody.length());
        while (prefix < prefixLimit && originalBody.charAt(prefix) == modifiedBody.charAt(prefix)) {
            prefix++;
        }

        int originalSuffix = originalBody.length() - 1;
        int modifiedSuffix = modifiedBody.length() - 1;
        while (originalSuffix >= prefix
                && modifiedSuffix >= prefix
                && originalBody.charAt(originalSuffix) == modifiedBody.charAt(modifiedSuffix)) {
            originalSuffix--;
            modifiedSuffix--;
        }

        if (modifiedSuffix < prefix) {
            return "";
        }

        return modifiedBody.substring(prefix, modifiedSuffix + 1);
    }

    private static boolean looksLikeCiphertextMutation(String originalBody, String modifiedBody) {
        if (originalBody == null || modifiedBody == null || originalBody.isEmpty()) {
            return false;
        }

        if (originalBody.equals(modifiedBody)) {
            return true;
        }

        int prefix = 0;
        int prefixLimit = Math.min(originalBody.length(), modifiedBody.length());
        while (prefix < prefixLimit && originalBody.charAt(prefix) == modifiedBody.charAt(prefix)) {
            prefix++;
        }

        int suffix = 0;
        int originalSuffix = originalBody.length() - 1;
        int modifiedSuffix = modifiedBody.length() - 1;
        while (originalSuffix >= prefix
                && modifiedSuffix >= prefix
                && originalBody.charAt(originalSuffix) == modifiedBody.charAt(modifiedSuffix)) {
            suffix++;
            originalSuffix--;
            modifiedSuffix--;
        }

        int threshold = Math.min(8, originalBody.length());
        return prefix >= threshold || suffix >= threshold;
    }

    private static String injectPayloadIntoPlaintext(String plaintext, String payload) {
        String jsonInjection = appendToLastJsonStringValue(plaintext, payload);
        if (jsonInjection != null) {
            return jsonInjection;
        }

        String formInjection = appendToLastFormValue(plaintext, payload);
        if (formInjection != null) {
            return formInjection;
        }

        return plaintext + payload;
    }

    private static String appendToLastJsonStringValue(String plaintext, String payload) {
        Matcher matcher = JSON_STRING.matcher(plaintext);
        int valueEnd = -1;
        while (matcher.find()) {
            valueEnd = matcher.end(2);
        }

        if (valueEnd < 0) {
            return null;
        }

        return plaintext.substring(0, valueEnd) + payload + plaintext.substring(valueEnd);
    }

    private static String appendToLastFormValue(String plaintext, String payload) {
        Matcher matcher = FORM_PARAM.matcher(plaintext);
        int valueEnd = -1;
        while (matcher.find()) {
            valueEnd = matcher.end(2);
        }

        if (valueEnd < 0) {
            return null;
        }

        return plaintext.substring(0, valueEnd) + payload + plaintext.substring(valueEnd);
    }

    /**
     * Truncates a string to {@value PREVIEW_LEN} characters and appends "…" if needed.
     *
     * @param s the string to preview
     * @return the preview string
     */
    private static String preview(String s) {
        if (s.length() <= PREVIEW_LEN) return s;
        return s.substring(0, PREVIEW_LEN) + "\u2026";
    }

    /**
     * Returns the request URL, or a safe fallback string if the request is malformed.
     *
     * @param request the request to extract the URL from
     * @return the URL string or a fallback
     */
    private static String safeUrl(HttpRequestToBeSent request) {
        try {
            return request.url();
        } catch (Exception e) {
            return "(malformed URL)";
        }
    }
}
