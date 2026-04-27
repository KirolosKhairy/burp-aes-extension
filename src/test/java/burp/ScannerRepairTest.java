package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Standalone scanner repair test with no Burp API dependencies.
 *
 * <p>This mirrors the repair heuristic used by {@code AesHttpLogger}:
 * diff the corrupted ciphertext against the original ciphertext to recover
 * the injected payload, append that payload to the last JSON string value,
 * then re-encrypt and verify the repaired request decrypts successfully.
 */
public class ScannerRepairTest {

    private static final String KEY_HEX = "0123456789abcdef0123456789abcdef";
    private static final String IV_HEX = "abcdef0123456789abcdef0123456789";
    private static final String PLAINTEXT = "{\"username\":\"admin\",\"password\":\"secret123\"}";

    private static final Pattern JSON_STRING =
            Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern FORM_PARAM =
            Pattern.compile("(?:^|(?<=&))([^=&]+)=([^&]*)");

    public static void main(String[] args) throws Exception {
        String validBase64 = encrypt(PLAINTEXT, KEY_HEX, IV_HEX);

        Tracker tracker = new Tracker();

        runCase(
                tracker,
                "Append payload at end",
                validBase64,
                PLAINTEXT,
                validBase64 + "btx:o",
                "btx:o",
                false);

        runCase(
                tracker,
                "Insert payload in middle",
                validBase64,
                PLAINTEXT,
                validBase64.substring(0, 20) + "<script>" + validBase64.substring(20),
                "<script>",
                false);

        runCase(
                tracker,
                "Replace part of Base64",
                validBase64,
                PLAINTEXT,
                validBase64.substring(0, 10) + "' OR 1=1--" + validBase64.substring(30),
                "' OR 1=1--",
                false);

        System.out.println();
        System.out.println("SUMMARY: " + tracker.passed + "/" + tracker.total + " checks passed");
        System.out.println(tracker.passed == tracker.total ? "OVERALL: PASS" : "OVERALL: FAIL");
    }

    private static void runCase(Tracker tracker,
                                String caseName,
                                String originalCiphertext,
                                String originalPlaintext,
                                String corruptedBody,
                                String expectedPayload,
                                boolean expectRecoverableByStripping) throws Exception {
        System.out.println();
        System.out.println("CASE: " + caseName);

        boolean validBase64 = isValidBase64(corruptedBody);
        tracker.check(caseName, "Corrupted body is not valid Base64", !validBase64);

        String stripped = stripNonBase64(corruptedBody);
        boolean recoveredByStripping = originalCiphertext.equals(stripped);
        tracker.check(
                caseName,
                "Removing non-Base64 chars recovers original ciphertext == " + expectRecoverableByStripping,
                recoveredByStripping == expectRecoverableByStripping);

        String extractedPayload = extractInjectedPayload(originalCiphertext, corruptedBody);
        tracker.check(
                caseName,
                "Payload extracted correctly",
                expectedPayload.equals(extractedPayload));

        String repairedCiphertext = repairCiphertext(originalCiphertext, originalPlaintext, corruptedBody);

        boolean repairedDecrypts = false;
        String repairedPlaintext = "";
        try {
            repairedPlaintext = decrypt(repairedCiphertext, KEY_HEX, IV_HEX);
            repairedDecrypts = true;
        } catch (Exception e) {
            repairedDecrypts = false;
        }

        tracker.check(caseName, "Repaired ciphertext decrypts successfully", repairedDecrypts);
        tracker.check(
                caseName,
                "Repaired plaintext contains payload",
                repairedDecrypts && repairedPlaintext.contains(expectedPayload));

        if (repairedDecrypts) {
            System.out.println("INFO [" + caseName + "] repaired plaintext: " + repairedPlaintext);
        }
    }

    private static String repairCiphertext(String originalCiphertext,
                                           String originalPlaintext,
                                           String corruptedBody) throws Exception {
        if (originalCiphertext.equals(corruptedBody)) {
            return originalCiphertext;
        }

        String payload = extractInjectedPayload(originalCiphertext, corruptedBody);
        if (payload.isEmpty()) {
            return originalCiphertext;
        }

        String repairedPlaintext = injectPayloadIntoPlaintext(originalPlaintext, payload);
        return encrypt(repairedPlaintext, KEY_HEX, IV_HEX);
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

    private static boolean isValidBase64(String value) {
        try {
            Base64.getDecoder().decode(value.trim());
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static String stripNonBase64(String value) {
        StringBuilder cleaned = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (isBase64Char(c)) {
                cleaned.append(c);
            }
        }
        return cleaned.toString();
    }

    private static boolean isBase64Char(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '+'
                || c == '/'
                || c == '=';
    }

    private static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Odd-length hex string: " + hex);
        }

        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static String encrypt(String plaintext, String hexKey, String hexIv) throws Exception {
        byte[] keyBytes = hexToBytes(hexKey);
        byte[] ivBytes = hexToBytes(hexIv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decrypt(String base64Ciphertext, String hexKey, String hexIv) throws Exception {
        byte[] keyBytes = hexToBytes(hexKey);
        byte[] ivBytes = hexToBytes(hexIv);
        byte[] ciphertext = Base64.getDecoder().decode(base64Ciphertext.trim());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new IvParameterSpec(ivBytes));

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private static final class Tracker {
        private int total;
        private int passed;

        private void check(String caseName, String description, boolean ok) {
            total++;
            if (ok) {
                passed++;
            }

            System.out.println((ok ? "PASS" : "FAIL") + " [" + caseName + "] " + description);
        }
    }
}
