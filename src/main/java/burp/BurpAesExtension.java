package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

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
}
