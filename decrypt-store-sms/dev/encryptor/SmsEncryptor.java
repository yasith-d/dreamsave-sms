import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public class SmsEncryptor {

    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String HMAC_ALGO = "HmacSHA256";

    // MUST MATCH the Cloud Function's SHARED_SECRET
    private static final String SHARED_SECRET = "";

    // === Derive AES-256 key exactly like Node.js (HMAC-SHA256(secret)) ===
    private static byte[] deriveAesKey() throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        SecretKeySpec keySpec = new SecretKeySpec(
                SHARED_SECRET.getBytes(StandardCharsets.UTF_8),
                HMAC_ALGO
        );
        mac.init(keySpec);
        return mac.doFinal();  // 32-byte AES-256 key
    }

    // === AES-GCM encrypt CSV -> Base64(iv + cipher+tag) ===
    public static String encryptCsv(String csvText) throws Exception {
        byte[] keyBytes = deriveAesKey();
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance(AES_MODE);

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcm);

        byte[] cipherBytes = cipher.doFinal(csvText.getBytes(StandardCharsets.UTF_8));

        // output format: iv || (ciphertext+tag)
        byte[] out = new byte[iv.length + cipherBytes.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipherBytes, 0, out, iv.length, cipherBytes.length);

        return Base64.getEncoder().encodeToString(out);
    }

    // === Build DS:<encryptedPayload> ===
    public static String buildEncryptedSms(
            String groupId,
            String meetingId,
            int versionInt,
            long timestampSeconds
    ) throws Exception {

        // Build EXACT CSV required by the Cloud Function
        String csv = String.format(
                "%s,%s,%d,%d",
                groupId,
                meetingId,
                versionInt,
                timestampSeconds
        );

        String encrypted = encryptCsv(csv);
        return "DS:" + encrypted;
    }

    // Example usage
    public static void main(String[] args) throws Exception {

        String groupId = UUID.randomUUID().toString();
        String meetingId = UUID.randomUUID().toString();
        int versionInt = 2170;
        long timestampSeconds = 1764134855;

        String sms = buildEncryptedSms(groupId, meetingId, versionInt, timestampSeconds);

        System.out.println("=== Encrypted SMS ===");
        System.out.println(sms);
    }
}