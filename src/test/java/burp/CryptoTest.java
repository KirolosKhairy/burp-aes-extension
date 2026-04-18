package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Self-contained AES/CBC/PKCS5Padding encrypt/decrypt test suite.
 *
 * Run after building:
 *   java -cp build/libs/burp-aes-extension.jar burp.CryptoTest
 * Or compile + run standalone:
 *   javac src/test/java/burp/CryptoTest.java -d out/
 *   java -cp out/ burp.CryptoTest
 */
public class CryptoTest {

    // ── Test key / IV ─────────────────────────────────────────────────────────
    static final String TEST_KEY = "0123456789abcdef0123456789abcdef"; // 32 hex chars → 128-bit
    static final String TEST_IV  = "abcdef0123456789abcdef0123456789"; // 32 hex chars → 16 bytes

    // ── Pass/fail counters ────────────────────────────────────────────────────
    private static int passed = 0;
    private static int failed = 0;

    // ── Entry point ───────────────────────────────────────────────────────────

    public static void main(String[] args) {
        System.out.println("=======================================================");
        System.out.println("  CryptoTest — AES/CBC/PKCS5Padding round-trip tests");
        System.out.println("=======================================================\n");

        testRoundTrip_knownKeyIv();
        testRoundTrip_emptyString();
        testRoundTrip_longString();
        testRoundTrip_specialAndUnicode();
        testInvalidBase64();
        testWrongKeyLength();
        testWrongIvLength();
        testPaddingBoundaries();

        System.out.println("\n=======================================================");
        System.out.printf("  Results: %d PASSED, %d FAILED%n", passed, failed);
        System.out.println("=======================================================");

        if (failed > 0) {
            System.exit(1);
        }
    }

    // ── Individual test methods ───────────────────────────────────────────────

    /** Round-trip with a known key and IV; verify ciphertext is deterministic. */
    static void testRoundTrip_knownKeyIv() {
        String label = "Round-trip: known key/IV with 'Hello, World!'";
        try {
            String plain     = "Hello, World!";
            String encrypted = encrypt(plain.getBytes(StandardCharsets.UTF_8), TEST_KEY, TEST_IV);
            byte[] decBytes  = decrypt(encrypted, TEST_KEY, TEST_IV);
            String recovered = new String(decBytes, StandardCharsets.UTF_8);

            if (!plain.equals(recovered)) {
                fail(label, "Expected '" + plain + "' but got '" + recovered + "'");
                return;
            }
            // Verify ciphertext is non-empty Base64
            if (encrypted == null || encrypted.isEmpty()) {
                fail(label, "Ciphertext was empty");
                return;
            }
            // Verify determinism: same plaintext + key + IV must yield same ciphertext
            String encrypted2 = encrypt(plain.getBytes(StandardCharsets.UTF_8), TEST_KEY, TEST_IV);
            if (!encrypted.equals(encrypted2)) {
                fail(label, "Ciphertext not deterministic");
                return;
            }
            pass(label);
        } catch (Exception e) {
            fail(label, e.toString());
        }
    }

    /** Encrypt/decrypt the empty string — should produce empty plaintext back. */
    static void testRoundTrip_emptyString() {
        String label = "Round-trip: empty string";
        try {
            byte[] plainBytes = new byte[0];
            String encrypted  = encrypt(plainBytes, TEST_KEY, TEST_IV);
            byte[] recovered  = decrypt(encrypted, TEST_KEY, TEST_IV);

            if (recovered.length != 0) {
                fail(label, "Expected 0 bytes back, got " + recovered.length);
                return;
            }
            pass(label);
        } catch (Exception e) {
            fail(label, e.toString());
        }
    }

    /** Encrypt/decrypt a string of 1000+ characters. */
    static void testRoundTrip_longString() {
        String label = "Round-trip: long string (1234 chars)";
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 1234; i++) sb.append((char) ('a' + (i % 26)));
            String plain     = sb.toString();
            String encrypted = encrypt(plain.getBytes(StandardCharsets.UTF_8), TEST_KEY, TEST_IV);
            byte[] decBytes  = decrypt(encrypted, TEST_KEY, TEST_IV);
            String recovered = new String(decBytes, StandardCharsets.UTF_8);

            if (!plain.equals(recovered)) {
                fail(label, "Long string did not round-trip correctly (first diff at char "
                        + firstDiff(plain, recovered) + ")");
                return;
            }
            pass(label);
        } catch (Exception e) {
            fail(label, e.toString());
        }
    }

    /** Encrypt/decrypt special ASCII characters and multi-byte Unicode. */
    static void testRoundTrip_specialAndUnicode() {
        String label = "Round-trip: special chars + Unicode (emoji, CJK, Latin-ext)";
        try {
            // Tab, newline, null byte, backslash, quotes, high-plane emoji, CJK, Latin
            String plain = "tab:\there\nnewline\0null \"quotes\" \\back\\ \uD83D\uDE00 \u4E2D\u6587 caf\u00E9";
            String encrypted = encrypt(plain.getBytes(StandardCharsets.UTF_8), TEST_KEY, TEST_IV);
            byte[] decBytes  = decrypt(encrypted, TEST_KEY, TEST_IV);
            String recovered = new String(decBytes, StandardCharsets.UTF_8);

            if (!plain.equals(recovered)) {
                fail(label, "Unicode string did not round-trip. Expected length "
                        + plain.length() + ", got " + recovered.length());
                return;
            }
            pass(label);
        } catch (Exception e) {
            fail(label, e.toString());
        }
    }

    /** Passing invalid Base64 to decrypt() must throw, not silently corrupt or crash. */
    static void testInvalidBase64() {
        String label = "Invalid Base64 input to decrypt() → must throw";
        try {
            decrypt("not!!valid%%base64###", TEST_KEY, TEST_IV);
            fail(label, "Expected an exception but none was thrown");
        } catch (Exception e) {
            // Expected — any exception type is acceptable
            pass(label + " [threw: " + e.getClass().getSimpleName() + "]");
        }
    }

    /** A key shorter than 16 bytes must be rejected by the JCE. */
    static void testWrongKeyLength() {
        String label = "Wrong key length (8 hex chars = 4 bytes) → must throw";
        try {
            encrypt("test".getBytes(StandardCharsets.UTF_8), "deadbeef", TEST_IV);
            fail(label, "Expected an exception but none was thrown");
        } catch (Exception e) {
            pass(label + " [threw: " + e.getClass().getSimpleName() + "]");
        }
    }

    /** An IV shorter than 16 bytes must be rejected by the JCE. */
    static void testWrongIvLength() {
        String label = "Wrong IV length (8 hex chars = 4 bytes) → must throw";
        try {
            encrypt("test".getBytes(StandardCharsets.UTF_8), TEST_KEY, "deadbeef");
            fail(label, "Expected an exception but none was thrown");
        } catch (Exception e) {
            pass(label + " [threw: " + e.getClass().getSimpleName() + "]");
        }
    }

    /**
     * Tests padding correctness for all plaintext lengths 1..33 bytes.
     *
     * AES block size = 16 bytes. PKCS5/7 padding adds 1..16 bytes so the ciphertext
     * length is always a multiple of 16. After decryption the padding must be stripped,
     * yielding exactly the original byte count.
     *
     * Key boundary: length=16 should produce 32 bytes of ciphertext (full-block padding);
     * lengths 1-15 → 16 bytes; length=17 → 32 bytes; length=32 → 48 bytes; length=33 → 48 bytes.
     */
    static void testPaddingBoundaries() {
        System.out.println("\n  [Padding boundary tests — lengths 1..33]");
        int subPassed = 0, subFailed = 0;

        for (int len = 1; len <= 33; len++) {
            String subLabel = "Padding: len=" + len;
            try {
                byte[] plain = new byte[len];
                Arrays.fill(plain, (byte) 0x41); // 'A' * len

                String encrypted = encrypt(plain, TEST_KEY, TEST_IV);

                // Verify ciphertext is a multiple of 16 bytes
                byte[] cipherBytes = Base64.getDecoder().decode(encrypted);
                if (cipherBytes.length % 16 != 0) {
                    fail(subLabel, "Ciphertext length " + cipherBytes.length + " is not a multiple of 16");
                    subFailed++;
                    continue;
                }

                // Verify expected ciphertext length: ceil(len/16)*16 + 16 for full-block padding at boundary
                int expectedBlocks = (len / 16) + 1; // always at least 1 padding block
                int expectedCipherLen = expectedBlocks * 16;
                if (cipherBytes.length != expectedCipherLen) {
                    fail(subLabel, "Expected " + expectedCipherLen + " cipher bytes, got " + cipherBytes.length);
                    subFailed++;
                    continue;
                }

                // Verify round-trip
                byte[] recovered = decrypt(encrypted, TEST_KEY, TEST_IV);
                if (!Arrays.equals(plain, recovered)) {
                    fail(subLabel, "Bytes differ after round-trip");
                    subFailed++;
                    continue;
                }

                System.out.printf("    PASS  len=%-3d → %d cipher bytes%n", len, cipherBytes.length);
                subPassed++;
            } catch (Exception e) {
                fail(subLabel, e.toString());
                subFailed++;
            }
        }

        passed += subPassed;
        failed += subFailed;
        System.out.printf("  Padding sub-total: %d PASSED, %d FAILED%n\n", subPassed, subFailed);
    }

    // ── Inline AES/CBC/PKCS5Padding helpers (no Burp API dependency) ──────────

    private static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) return new byte[0];
        hex = hex.replaceAll("\\s+", "");
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    static String encrypt(byte[] plaintext, String hexKey, String hexIv) throws Exception {
        byte[] keyBytes = hexToBytes(hexKey);
        byte[] ivBytes  = hexToBytes(hexIv);
        SecretKeySpec  keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
    }

    static byte[] decrypt(String base64Ciphertext, String hexKey, String hexIv) throws Exception {
        byte[] keyBytes  = hexToBytes(hexKey);
        byte[] ivBytes   = hexToBytes(hexIv);
        byte[] ciphertext = Base64.getDecoder().decode(base64Ciphertext.trim());
        SecretKeySpec   keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec  = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    // ── Reporting helpers ─────────────────────────────────────────────────────

    private static void pass(String label) {
        System.out.println("  PASS  " + label);
        passed++;
    }

    private static void fail(String label, String reason) {
        System.out.println("  FAIL  " + label);
        System.out.println("        Reason: " + reason);
        failed++;
    }

    private static int firstDiff(String a, String b) {
        int len = Math.min(a.length(), b.length());
        for (int i = 0; i < len; i++) {
            if (a.charAt(i) != b.charAt(i)) return i;
        }
        return len;
    }
}
