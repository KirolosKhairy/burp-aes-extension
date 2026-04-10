package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

/**
 * A single scanner insertion point that lives inside an AES-encrypted request body.
 *
 * <p>When Burp supplies a payload:
 * <ol>
 *   <li>The payload is spliced into the decrypted body at {@code [valueStart, valueEnd)}.</li>
 *   <li>The modified plaintext is re-encrypted via {@link CryptoHelper}.</li>
 *   <li>The base request is returned with the new encrypted body
 *       ({@code withBody()} also updates {@code Content-Length} automatically).</li>
 * </ol>
 *
 * <p>{@link #issueHighlights(ByteArray)} returns an empty list because the raw payload
 * never appears literally in the encrypted wire bytes — there is no meaningful byte offset
 * to highlight in the raw HTTP request.
 */
public class AesInsertionPoint implements AuditInsertionPoint {

    private final BurpAesExtension extension;
    private final HttpRequest       baseRequest;
    private final String            decryptedBody;
    private final String            paramName;
    private final String            paramValue;
    private final int               valueStart; // inclusive offset within decryptedBody
    private final int               valueEnd;   // exclusive offset within decryptedBody
    private volatile String         lastPayload = "";

    /**
     * @param extension     the shared extension state (key, IV)
     * @param baseRequest   the original HTTP request whose encrypted body will be replaced
     * @param decryptedBody the full decrypted plaintext of the request body
     * @param paramName     the parameter name (used as the insertion point label)
     * @param paramValue    the original parameter value (returned by {@link #baseValue()})
     * @param valueStart    inclusive start offset of the value within {@code decryptedBody}
     * @param valueEnd      exclusive end offset of the value within {@code decryptedBody}
     */
    public AesInsertionPoint(BurpAesExtension extension,
                              HttpRequest baseRequest,
                              String decryptedBody,
                              String paramName,
                              String paramValue,
                              int valueStart,
                              int valueEnd) {
        this.extension     = extension;
        this.baseRequest   = baseRequest;
        this.decryptedBody = decryptedBody;
        this.paramName     = paramName;
        this.paramValue    = paramValue;
        this.valueStart    = valueStart;
        this.valueEnd      = valueEnd;
    }

    /**
     * @return the parameter name used as the insertion point label in Burp's UI
     */
    @Override
    public String name() {
        return paramName;
    }

    /**
     * @return the original parameter value from the base request
     */
    @Override
    public String baseValue() {
        return paramValue;
    }

    /**
     * Builds a new HTTP request with the given payload substituted into the encrypted body.
     *
     * <p>The payload is inserted at the tracked offsets in the decrypted body, the modified
     * plaintext is AES re-encrypted, and the result replaces the request body.
     *
     * @param payload the raw (non-encoded) payload bytes from the scanner
     * @return the modified HTTP request with the re-encrypted body, or the original request
     *         if re-encryption fails
     */
    @Override
    public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
        String payloadStr = new String(payload.getBytes(), StandardCharsets.UTF_8);
        lastPayload = payloadStr;

        String modifiedBody = decryptedBody.substring(0, valueStart)
                + payloadStr
                + decryptedBody.substring(valueEnd);

        try {
            String encrypted = extension.getCryptoHelper().encrypt(
                    modifiedBody.getBytes(StandardCharsets.UTF_8));
            return baseRequest.withBody(encrypted);
        } catch (Exception e) {
            extension.getLogging().logToError(
                    "AesInsertionPoint [" + paramName + "]: re-encryption failed: " + e.getMessage());
            return baseRequest;
        }
    }

    /**
     * Returns the most recent raw payload supplied by Burp Scanner for this insertion point.
     *
     * @return the last injected payload, or an empty string if none has been injected yet
     */
    public String getLastPayload() {
        return lastPayload;
    }

    /**
     * Returns an empty list because the payload has no literal position in the encrypted
     * request bytes — highlighting is not applicable for this insertion point type.
     *
     * @param payload the payload (unused)
     * @return an empty list
     */
    @Override
    public List<Range> issueHighlights(ByteArray payload) {
        return Collections.emptyList();
    }

    /**
     * @return {@link AuditInsertionPointType#EXTENSION_PROVIDED}
     */
    @Override
    public AuditInsertionPointType type() {
        return AuditInsertionPointType.EXTENSION_PROVIDED;
    }
}
