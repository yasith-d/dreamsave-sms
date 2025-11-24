import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public class SmsGcmEncryptTest {

    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    // Use the same secret as the cloud function
    private static final String SHARED_SECRET = "4pR$Z9!nV@u2#tC7^hL6%yK1*fM3&eX5";

    // === Key derivation ===
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

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

        // Combine IV + ciphertext+tag
        byte[] out = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(out);
    }

    // === Build SMS according to new payload ===
    public static String encryptMessageForSms(String groupNumber, String meetingNumber, long timestamp, String version) throws Exception {
        String meetingId = UUID.randomUUID().toString(); // unique id for this meeting
        String jsonPayload = String.format(
                "{\"t\":%d,\"id\":\"%s\",\"n\":\"%s\",\"v\":\"%s\"}",
                timestamp,
                meetingId,
                meetingNumber,
                version
        );

        String encrypted = encryptGcm(jsonPayload, groupNumber);
        return "DreamStart:" + groupNumber + ":" + meetingNumber + ":" + encrypted;
    }

    public static void main(String[] args) throws Exception {
        // === Example usage ===
        String groupNumber = "SS-903-184";
        String meetingNumber = "M#4";
        long timestamp = System.currentTimeMillis();
        String version = "2.17.0-dev.beta";

        String sms = encryptMessageForSms(groupNumber, meetingNumber, timestamp, version);

        System.out.println("=== Final SMS Content ===");
        System.out.println(sms);
    }
}
