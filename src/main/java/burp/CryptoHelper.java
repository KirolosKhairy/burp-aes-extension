package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * AES/CBC/PKCS5Padding encryption and decryption utility.
 *
 * <p>The key and IV are read from the extension's shared state at call time, so changes
 * made in the Config tab take effect immediately without restarting the extension.
 */
public class CryptoHelper {

    private final BurpAesExtension extension;

    /**
     * @param extension the shared extension state that holds the current key and IV
     */
    public CryptoHelper(BurpAesExtension extension) {
        this.extension = extension;
    }

    private byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) return new byte[0];
        hex = hex.replaceAll("\\s+", "");
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Odd-length hex string: " + hex);
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Encrypts plaintext bytes using AES/CBC/PKCS5Padding with the current key and IV.
     *
     * @param plaintext the raw bytes to encrypt
     * @return Base64-encoded ciphertext string
     * @throws Exception if the key or IV is invalid, or encryption fails
     */
    public String encrypt(byte[] plaintext) throws Exception {
        byte[] keyBytes = hexToBytes(extension.getAesKey());
        byte[] ivBytes = hexToBytes(extension.getAesIv());

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] encrypted = cipher.doFinal(plaintext);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts a Base64-encoded ciphertext using AES/CBC/PKCS5Padding with the current key and IV.
     *
     * @param base64Ciphertext the Base64-encoded ciphertext (leading/trailing whitespace is trimmed)
     * @return plaintext bytes
     * @throws Exception if the key or IV is invalid, Base64 decoding fails, or decryption fails
     */
    public byte[] decrypt(String base64Ciphertext) throws Exception {
        byte[] keyBytes = hexToBytes(extension.getAesKey());
        byte[] ivBytes = hexToBytes(extension.getAesIv());

        byte[] ciphertext = Base64.getDecoder().decode(base64Ciphertext.trim());

        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(ciphertext);
    }
}
