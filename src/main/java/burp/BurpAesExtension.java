package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Entry point for the AES Traffic Decryptor Burp Suite extension.
 *
 * <p>Holds shared volatile state (AES key, IV, target host) that is read by all
 * other components. Wires together:
 * <ul>
 *   <li>{@link ConfigTab} — Suite tab for configuring crypto settings.</li>
 *   <li>{@link DecryptedMessageTabFactory} — "decrypted_message" tab in HTTP History
 *       and Repeater.</li>
 *   <li>{@link AesHttpLogger} — HTTP handler that logs and highlights AES traffic.</li>
 *   <li>{@link AesScanCheck} — Scanner insertion point provider (Pro only).</li>
 *   <li>{@link AesResponseScanCheck} — Scanner check that inspects decrypted responses.</li>
 * </ul>
 */
public class BurpAesExtension implements BurpExtension {

    private volatile String aesKey     = "";
    private volatile String aesIv      = "";
    private volatile String targetHost = "";

    private CryptoHelper cryptoHelper;
    private Logging      logging;
    private final Map<String, ScanRequestContext> scanRequestContexts = new ConcurrentHashMap<>();

    /**
     * Called by Burp at load time. Registers all extension components.
     *
     * @param api the Montoya API
     */
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("AES Traffic Decryptor");
        this.logging      = api.logging();
        this.cryptoHelper = new CryptoHelper(this);

        String savedKey = api.persistence().extensionData().getString("aesKey");
        String savedIv = api.persistence().extensionData().getString("aesIv");
        String savedHost = api.persistence().extensionData().getString("targetHost");

        setAesKey(savedKey != null ? savedKey : "");
        setAesIv(savedIv != null ? savedIv : "");
        setTargetHost(savedHost != null ? savedHost : "");

        // Config tab
        ConfigTab configTab = new ConfigTab(this, api);
        api.userInterface().registerSuiteTab("AES Config", configTab.getPanel());

        // Decrypted message tab in HTTP History + Repeater
        DecryptedMessageTabFactory tabFactory = new DecryptedMessageTabFactory(this);
        api.userInterface().registerHttpRequestEditorProvider(tabFactory);
        api.userInterface().registerHttpResponseEditorProvider(tabFactory);

        // HTTP logger + highlight handler
        api.http().registerHttpHandler(new AesHttpLogger(this, api));
        logging.logToOutput("AES HTTP logger registered.");

        // Scanner insertion point provider + decrypted response scan check (Professional only)
        try {
            api.scanner().registerInsertionPointProvider(new AesScanCheck(this));
            api.scanner().registerScanCheck(new AesResponseScanCheck(this, api));
            logging.logToOutput("AES insertion point provider registered.");
            logging.logToOutput("AES decrypted response scan check registered.");
        } catch (Exception e) {
            logging.logToOutput("Scanner not available (Community Edition?): " + e.getMessage());
        }

        if (!aesKey.isEmpty() && !aesIv.isEmpty() && !targetHost.isEmpty()) {
            logging.logToOutput("Saved AES configuration loaded from extension persistence.");
        }
        logging.logToOutput("AES Traffic Decryptor loaded successfully.");
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /** @return the current AES key as a hex string */
    public String getAesKey() { return aesKey; }

    /** @return the current IV as a hex string */
    public String getAesIv()  { return aesIv; }

    /** @return the configured target hostname substring */
    public String getTargetHost() { return targetHost; }

    /**
     * Updates the AES key used by {@link CryptoHelper}.
     * @param key hex-encoded AES key (32, 48, or 64 chars)
     */
    public void setAesKey(String key)  { this.aesKey     = key; }

    /**
     * Updates the IV used by {@link CryptoHelper}.
     * @param iv hex-encoded 16-byte IV (32 chars)
     */
    public void setAesIv(String iv)    { this.aesIv      = iv; }

    /**
     * Updates the target host filter. Only traffic whose host contains this string
     * will be processed by the extension.
     * @param host hostname or hostname fragment to match
     */
    public void setTargetHost(String host) { this.targetHost = host; }

    /** @return the shared {@link CryptoHelper} instance */
    public CryptoHelper getCryptoHelper() { return cryptoHelper; }

    /** @return Burp's {@link Logging} interface for output and error logging */
    public Logging getLogging() { return logging; }

    /**
     * Stores the original encrypted/decrypted body for a request currently being actively audited.
     * The scanner uses extension insertion points <em>in addition to</em> its built-in insertion
     * points, so the HTTP handler needs access to the original body in order to repair requests
     * whose encrypted Base64 body was corrupted by Burp's default insertion points.
     *
     * @param request        the base HTTP request being audited
     * @param encryptedBody  the original encrypted Base64 body
     * @param decryptedBody  the decrypted plaintext body
     */
    public void rememberScanRequest(HttpRequest request, String encryptedBody, String decryptedBody) {
        if (request == null || encryptedBody == null || encryptedBody.isEmpty()) {
            return;
        }

        if (scanRequestContexts.size() > 512) {
            scanRequestContexts.clear();
        }

        scanRequestContexts.put(scanRequestKey(request), new ScanRequestContext(encryptedBody, decryptedBody));
    }

    /**
     * Looks up the stored scanner context for a request using a fingerprint that ignores the body,
     * content length, and internal extension marker header.
     *
     * @param request the outbound request
     * @return the matching stored context, or {@code null} if none exists
     */
    public ScanRequestContext scanRequestContextFor(HttpRequest request) {
        if (request == null) {
            return null;
        }
        return scanRequestContexts.get(scanRequestKey(request));
    }

    private static String scanRequestKey(HttpRequest request) {
        StringBuilder key = new StringBuilder();

        try {
            key.append(request.httpService().host()).append('|')
                    .append(request.httpService().port()).append('|')
                    .append(request.httpService().secure());
        } catch (Exception e) {
            key.append("unknown-service");
        }

        try {
            key.append('|').append(request.method());
        } catch (Exception e) {
            key.append("|UNKNOWN");
        }

        try {
            key.append('|').append(request.path());
        } catch (Exception e) {
            key.append("|/");
        }

        try {
            for (HttpHeader header : request.headers()) {
                String name = header.name();
                if (name == null) {
                    continue;
                }

                String normalized = name.toLowerCase(Locale.ROOT);
                if ("content-length".equals(normalized)
                        || AesInsertionPoint.SCANNER_MARKER_HEADER.toLowerCase(Locale.ROOT).equals(normalized)) {
                    continue;
                }

                key.append('|').append(normalized).append('=').append(header.value());
            }
        } catch (Exception e) {
            // Ignore malformed headers and fall back to the service/method/path key only.
        }

        return key.toString();
    }

    /**
     * Snapshot of the original encrypted request body and its plaintext representation.
     */
    public static final class ScanRequestContext {
        private final String encryptedBody;
        private final String decryptedBody;

        private ScanRequestContext(String encryptedBody, String decryptedBody) {
            this.encryptedBody = encryptedBody;
            this.decryptedBody = decryptedBody;
        }

        public String encryptedBody() {
            return encryptedBody;
        }

        public String decryptedBody() {
            return decryptedBody;
        }
    }
}
