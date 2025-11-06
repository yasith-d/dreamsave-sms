// sms_decrypt_test.js
import crypto from "crypto";

const SHARED_SECRET = "4pR$Z9!nV@u2#tC7^hL6%yK1*fM3&eX5"; // same as in Java

// === Derive AES key ===
// HMAC-SHA256(sharedSecret, groupNumber) -> 32-byte key
function deriveAesKey(sharedSecret, groupNumber) {
  const hmac = crypto.createHmac("sha256", sharedSecret);
  hmac.update(groupNumber);
  return hmac.digest(); // returns Buffer of 32 bytes
}

// === AES-256-ECB decrypt ===
function decryptAesEcb(base64CipherText, keyBytes) {
  const decipher = crypto.createDecipheriv("aes-256-ecb", keyBytes, null);
  decipher.setAutoPadding(true);
  const encrypted = Buffer.from(base64CipherText, "base64");
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}

// === Decrypt full SMS payload ===
function decryptSmsPayload(smsContent) {
  const parts = smsContent.split(":");
  if (parts.length < 3) throw new Error("Invalid sms content format");
  if (parts[0] !== "dreamstart") throw new Error("Invalid tag");

  const groupNumber = parts[1];
  const base64 = parts.slice(2).join(":"); // in case ':' appears in ciphertext

  const keyBytes = deriveAesKey(SHARED_SECRET, groupNumber);
  return decryptAesEcb(base64, keyBytes);
}

// === Test with sample SMS ===
const sms = "dreamstart:LK-123-456:W/+dPj73PgL1kxCbEQLg3NZNkp2oN4nwG+GaLpNeHLk1Ml0yxxXiMXe4stZ5oidL";

try {
  const decrypted = decryptSmsPayload(sms);
  console.log("Decrypted message:", decrypted);
} catch (e) {
  console.error("Decryption failed:", e.message);
}
