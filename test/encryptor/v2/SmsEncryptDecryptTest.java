import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class SmsEncryptDecryptTest {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String AES_ALGORITHM = "AES/ECB/PKCS5Padding";
    private static final String SHARED_SECRET = ""; // same as GCP

    private static byte[] deriveAesKeyBytes(String sharedSecret, String groupNumber) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(sharedSecret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(groupNumber.getBytes(StandardCharsets.UTF_8)); // 32 bytes
    }

    public static String encrypt(String plaintext, byte[] keyBytes) throws Exception {
        SecretKeySpec aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String encryptMessageForSms(String groupNumber, String meetingId, String endedAtIso) throws Exception {
        String jsonPayload = String.format("{\"endedAt\":\"%s\"}", endedAtIso);
        byte[] keyBytes = deriveAesKeyBytes(SHARED_SECRET, groupNumber);
        String base64 = encrypt(jsonPayload, keyBytes);
        return "dreamstart:" + groupNumber + ":" + meetingId + ":" + base64;
    }

    public static void main(String[] args) throws Exception {
        String groupNumber = "MA-234-567";
        String meetingId = "MEET-001";
        String endedAtIso = "2025-11-14T12:33:00Z";

        String sms = encryptMessageForSms(groupNumber, meetingId, endedAtIso);
        System.out.println("Final SMS content:");
        System.out.println(sms);
    }
}
