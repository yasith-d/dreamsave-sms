const crypto = require("crypto");

// ***** SET THIS BEFORE USING *****
const SHARED_SECRET = "";

// === HMAC-based AES256 key derivation ===
function deriveAesKey(sharedSecret, groupNumber) {
    const hmac = crypto.createHmac("sha256", sharedSecret);
    hmac.update(groupNumber);
    return hmac.digest();
}

// === AES-256-GCM decryption ===
// base64Input = Base64( iv || ciphertext || tag )
function decryptAesGcm(base64Input, keyBytes) {
    const combined = Buffer.from(base64Input, "base64");
    const ivSize = 12;

    if (combined.length < ivSize + 16) {
        console.error("Invalid encrypted payload length");
        return null;
    }

    const iv = combined.subarray(0, ivSize);
    const cipherPlusTag = combined.subarray(ivSize);

    // split ciphertext and tag
    const tag = cipherPlusTag.subarray(cipherPlusTag.length - 16);
    const ciphertext = cipherPlusTag.subarray(0, cipherPlusTag.length - 16);

    try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes, iv);
        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]);

        return decrypted.toString("utf8");
    } catch (err) {
        console.error("AES-GCM decryption/authentication failed:", err.message);
        return null;
    }
}

// === Parse full SMS format ===
// DreamStart:GROUP:MEETING:BASE64
function parseSms(smsContent) {
    const parts = smsContent.split(":");

    if (parts.length < 4) {
        throw new Error("Invalid SMS format — expected 4 parts");
    }

    if (parts[0].toLowerCase() !== "dreamstart") {
        throw new Error("Invalid tag: expected 'DreamStart'");
    }

    const groupId = parts[1];
    const meetingId = parts[2];

    // Base64 may contain ':' so re-join
    const base64Cipher = parts.slice(3).join(":");

    const keyBytes = deriveAesKey(SHARED_SECRET, groupId);

    const decrypted = decryptAesGcm(base64Cipher, keyBytes);
    if (!decrypted) throw new Error("GCM decryption failed");

    // Decryption was successful
    return {
        groupId,
        meetingId,
        decrypted,
        encrypted: base64Cipher,
        raw: smsContent,
    };
}

// === Execution (CLI usage) ===
if (require.main === module) {
    const input = process.argv[2];

    if (!input) {
        console.log("\nUsage:");
        console.log('  node local_decrypt_test.js "DreamStart:XX-123:MEET-001:BASE64HERE"\n');
        process.exit(1);
    }

    console.log("\nDecrypting SMS...\n");

    try {
        const result = parseSms(input);

        console.log("SUCCESS — SMS parsed & decrypted:\n");
        console.log("Group Number:", result.groupId);
        console.log("Meeting Number:", result.meetingId);
        console.log("\nDecrypted JSON:");
        console.log(result.decrypted);

    } catch (err) {
        console.error("\nFAILED:", err.message);
    }
}
