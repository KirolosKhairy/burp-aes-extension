package burp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Standalone smoke test for the AES/CBC/PKCS5Padding auto-encrypt flow used by CryptoHelper.
 */
public class AutoEncryptTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";
    private static final String IV = "abcdef0123456789abcdef0123456789";
    private static final String PLAINTEXT = "{\"username\":\"admin\",\"password\":\"secret123\"}";

    public static void main(String[] args) throws Exception {
        TestCryptoHelper cryptoHelper = new TestCryptoHelper(KEY, IV);

        String encrypted = cryptoHelper.encrypt(PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        assertTrue(!PLAINTEXT.equals(encrypted), "Encrypted body must differ from plaintext");

        byte[] decoded = Base64.getDecoder().decode(encrypted);
        assertTrue(decoded.length > 0, "Encrypted body must be valid non-empty Base64");

        String decrypted = new String(cryptoHelper.decrypt(encrypted), StandardCharsets.UTF_8);
        assertTrue(PLAINTEXT.equals(decrypted), "Decrypted body must match original plaintext");

        System.out.println("AutoEncryptTest: PASS");
        System.out.println("plaintext -> encrypt -> Base64 -> decrypt -> original plaintext");
        System.out.println("Plaintext length: " + PLAINTEXT.getBytes(StandardCharsets.UTF_8).length);
        System.out.println("Encrypted Base64 length: " + encrypted.length());
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static final class TestCryptoHelper {
        private final String key;
        private final String iv;

        private TestCryptoHelper(String key, String iv) {
            this.key = key;
            this.iv = iv;
        }

        private String encrypt(byte[] plaintext) throws Exception {
            byte[] keyBytes = hexToBytes(key);
            byte[] ivBytes = hexToBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new IvParameterSpec(ivBytes));

            return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
        }

        private byte[] decrypt(String base64Ciphertext) throws Exception {
            byte[] keyBytes = hexToBytes(key);
            byte[] ivBytes = hexToBytes(iv);
            byte[] ciphertext = Base64.getDecoder().decode(base64Ciphertext.trim());

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new IvParameterSpec(ivBytes));

            return cipher.doFinal(ciphertext);
        }

        private static byte[] hexToBytes(String hex) {
            hex = hex.replaceAll("\\s+", "");
            byte[] data = new byte[hex.length() / 2];
            for (int i = 0; i < hex.length(); i += 2) {
                data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                        + Character.digit(hex.charAt(i + 1), 16));
            }
            return data;
        }
    }
}
