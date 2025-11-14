import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SmsGcmEncryptTest {

    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private static final String SHARED_SECRET = "";

    // === Key derivation (same as frontend) ===
    private static byte[] deriveAesKeyBytes(String sharedSecret, String groupNumber) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(groupNumber.getBytes(StandardCharsets.UTF_8)); // 32 bytes = AES-256
    }

    // === AES-GCM encrypt: output Base64( iv || ciphertext+tag ) ===
    public static String encryptGcm(String plainText, String groupNumber) throws Exception {
        byte[] keyBytes = deriveAesKeyBytes(SHARED_SECRET, groupNumber);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance(AES_MODE);

        // 12-byte IV recommended for GCM
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Combine IV + ciphertext+tag
        byte[] out = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(out);
    }

    // === Full SMS builder ===
    public static String encryptMessageForSms(String groupNumber, String meetingTitle, String endedAtIso) throws Exception {
        String jsonPayload = String.format("{\"endedAt\":\"%s\"}", endedAtIso);
        String encrypted = encryptGcm(jsonPayload, groupNumber);
        return "DreamStart:" + groupNumber + ":" + meetingTitle + ":" + encrypted;
    }

    public static void main(String[] args) throws Exception {
        // === Test data ===
        String groupNumber = "LK-243-648";
        String meetingTitle = "Meeting #3";
        String endedAtIso = "2025-11-14T12:33:00Z";

        String sms = encryptMessageForSms(groupNumber, meetingTitle, endedAtIso);

        System.out.println("=== Final SMS Content ===");
        System.out.println(sms);
    }
}
