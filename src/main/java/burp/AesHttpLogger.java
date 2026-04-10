package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

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
     * Intercepts outbound requests. If the host matches the target and the body is
     * AES-decryptable, logs a plaintext summary and marks the row CYAN.
     *
     * @param request information about the request about to be sent
     * @return a {@link RequestToBeSentAction} — always CONTINUE, never drops or modifies the body
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (!hostMatches(request.httpService().host())) {
            return RequestToBeSentAction.continueWith(request);
        }

        String body = request.bodyToString().trim();
        if (body.isEmpty()) {
            return RequestToBeSentAction.continueWith(request);
        }

        try {
            byte[] plaintext = extension.getCryptoHelper().decrypt(body);
            String preview   = preview(new String(plaintext, StandardCharsets.UTF_8));
            String time      = LocalTime.now().format(TIME_FMT);

            api.logging().logToOutput(
                    "[" + time + "] REQUEST  "
                    + request.method() + " " + safeUrl(request)
                    + "  |  Decrypted: " + preview);

            Annotations annotations = Annotations.annotations(HighlightColor.CYAN);
            return RequestToBeSentAction.continueWith(request, annotations);

        } catch (Exception e) {
            // Body is not AES-encrypted with the current key — pass through silently
            return RequestToBeSentAction.continueWith(request);
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
                && host != null && host.contains(target);
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
