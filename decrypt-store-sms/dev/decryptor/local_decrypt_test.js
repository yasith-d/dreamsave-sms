const crypto = require("crypto");

// ***** SET THIS BEFORE USING *****
const SHARED_SECRET = "";

// === Key derivation (match frontend/cloud function) ===
function deriveAesKeyFromSharedSecret(sharedSecret) {
    const hmac = crypto.createHmac("sha256", Buffer.from(sharedSecret, "utf8"));
    return hmac.digest(); // 32 bytes AES-256 key
}

// === AES-256-GCM decryption ===
// base64Input = Base64( iv(12) || ciphertext || tag(16) )
function decryptAesGcm(base64Input, keyBytes) {
    let combined;
    try {
        combined = Buffer.from(base64Input, "base64");
    } catch (err) {
        console.error("Base64 decode failed:", err.message);
        return null;
    }

    const ivSize = 12;
    if (combined.length < ivSize + 16) {
        console.error("Invalid payload length (iv + tag)");
        return null;
    }

    const iv = combined.subarray(0, ivSize);
    const cipherText = combined.subarray(ivSize);

    const tag = cipherText.subarray(cipherText.length - 16);
    const actualCipher = cipherText.subarray(0, cipherText.length - 16);

    try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(actualCipher), decipher.final()]);
        return decrypted.toString("utf8");
    } catch (err) {
        console.error("AES-GCM auth/tag failure:", err.message);
        return null;
    }
}

// === Parse DSL SMS ===
// Expect: DS:<base64(iv+ciphertext+tag)>
function parseDslSms(rawSms) {
    if (!rawSms) throw new Error("Empty SMS content");

    const idx = rawSms.indexOf(":");
    if (idx === -1) throw new Error("Invalid SMS format: missing ':'");

    const tag = rawSms.substring(0, idx).trim().toLowerCase();
    if (tag !== "ds") throw new Error("Invalid tag: expected 'DS'");

    const encryptedPart = rawSms.substring(idx + 1).trim();
    if (!encryptedPart) throw new Error("Empty DS encrypted payload");

    const keyBytes = deriveAesKeyFromSharedSecret(SHARED_SECRET);
    const decrypted = decryptAesGcm(encryptedPart, keyBytes);

    if (!decrypted) throw new Error("GCM decryption failed");

    // Split into 4 CSV fields (groupId, meetingId, versionInt, timestamp)
    const parts = decrypted.split(",").map(p => p.trim());
    if (parts.length !== 4) {
        throw new Error(`Invalid decrypted payload: expected 4 CSV fields, got ${parts.length}`);
    }

    const [groupId, meetingId, versionInt, timestamp] = parts;

    return {
        groupId,
        meetingId,
        versionInt,
        timestamp,
        decrypted,
        encrypted: encryptedPart,
        raw: rawSms
    };
}

// === CLI execution ===
if (require.main === module) {
    const input = process.argv[2];

    if (!input) {
        console.log("\nUsage:");
        console.log('  node local_decrypt_test.js "DS:BASE64PAYLOAD"\n');
        process.exit(1);
    }

    try {
        const result = parseDslSms(input);
        console.log("\nSUCCESS — SMS parsed & decrypted:\n");
        console.log("Group ID:", result.groupId);
        console.log("Meeting ID:", result.meetingId);
        console.log("Version:", result.versionInt);
        console.log("Timestamp:", result.timestamp);
        console.log("\nDecrypted message JSON:\n", result.decrypted);
    } catch (err) {
        console.error("\nFAILED:", err.message);
    }
}

module.exports = {
    deriveAesKeyFromSharedSecret,
    decryptAesGcm,
    parseDslSms
};
