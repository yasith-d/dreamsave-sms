import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 * Local tester for encrypting/decrypting DreamSave SMS payloads.
 * Derives AES-256 key by HMAC-SHA256(SHARED_SECRET, groupNumber) and using the 32-byte raw HMAC output as key.
 */
public class SmsEncryptDecryptTest {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";

    // Replace with the shared secret you will use in app / cloud function
    private static final String SHARED_SECRET = "4pR$Z9!nV@u2#tC7^hL6%yK1*fM3&eX5";

    /**
     * Derive 32-byte AES key from HMAC-SHA256(sharedSecret, groupNumber).
     * We return the raw 32 bytes (HMAC-SHA256 produces 32 bytes).
     */
    private static byte[] deriveAesKeyBytes(String sharedSecret, String groupNumber) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
        mac.init(keySpec);
        byte[] hmac = mac.doFinal(groupNumber.getBytes(StandardCharsets.UTF_8)); // 32 bytes
        // use full 32 bytes directly as AES-256 key
        return hmac;
    }

    /**
     * Encrypt plaintext with AES-256-ECB using keyBytes (32 bytes).
     * Returns Base64 string of the ciphertext.
     */
    public static String encrypt(String plaintext, byte[] keyBytes) throws Exception {
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt Base64 ciphertext with AES-256-ECB using keyBytes (32 bytes)
     */
    public static String decrypt(String base64CipherText, byte[] keyBytes) throws Exception {
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] encrypted = Base64.getDecoder().decode(base64CipherText);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Convenience: build "dreamstart:GROUP:ENCRYPTED" string for sending by SMS
     */
    public static String encryptMessageForSms(String groupNumber, String plaintext) throws Exception {
        byte[] keyBytes = deriveAesKeyBytes(SHARED_SECRET, groupNumber);
        String base64 = encrypt(plaintext, keyBytes);
        return "dreamstart:" + groupNumber + ":" + base64;
    }

    /**
     * Extract parts and decrypt smsContent (format "dreamstart:GROUP:BASE64")
     */
    public static String decryptSmsPayload(String smsContent) throws Exception {
        String[] parts = smsContent.split(":", 3);
        if (parts.length < 3) throw new IllegalArgumentException("Invalid sms content format");
        if (!"dreamstart".equals(parts[0])) throw new IllegalArgumentException("Invalid tag");
        String groupNumber = parts[1];
        String base64 = parts[2];
        byte[] keyBytes = deriveAesKeyBytes(SHARED_SECRET, groupNumber);
        return decrypt(base64, keyBytes);
    }

    // === main for demonstration ===
    public static void main(String[] args) throws Exception {
        // Example inputs - change them to test
        String groupNumber = "UG-456-789";
        // String message = "Meeting ended for group LK-123-456 at 10:00AM";
        String message = "Meeting ended for group UG-456-789 at 12:33PM";


        System.out.println("Original message: " + message);

        // Encrypt -> SMS content
        String sms = encryptMessageForSms(groupNumber, message);
        System.out.println("Final SMS content: " + sms);

        // Decrypt back (simulate cloud function)
        String recovered = decryptSmsPayload(sms);
        System.out.println("Decrypted message: " + recovered);

        // quick validation
        System.out.println("Match: " + message.equals(recovered));
    }
}
