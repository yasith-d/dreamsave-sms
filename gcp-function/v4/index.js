const functions = require('@google-cloud/functions-framework');
const crypto = require("crypto");

const SHARED_SECRET = process.env.SHARED_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

function deriveAesKey(sharedSecret, groupNumber) {
  const hmac = crypto.createHmac("sha256", sharedSecret);
  hmac.update(groupNumber);
  return hmac.digest();
}

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

function decryptSmsPayload(smsContent) {
  const parts = smsContent.split(":");
  if (parts.length < 3) throw new Error("Invalid sms content format");
  if (parts[0] !== "dreamstart") throw new Error("Invalid tag");

  const groupNumber = parts[1];
  const base64 = parts.slice(2).join(":");

  const keyBytes = deriveAesKey(SHARED_SECRET, groupNumber);
  return {
    groupNumber,
    message: decryptAesEcb(base64, keyBytes),
  };
}

// === Entry point ===
functions.http('decryptSMS', async (req, res) => {
  try {
    const providedSecret = req.body?.secret || req.headers["x-webhook-secret"];
    if (!providedSecret || providedSecret !== WEBHOOK_SECRET) {
      console.warn("Unauthorized request");
      return res.status(403).send("Forbidden");
    }

    const smsContent = req.body?.content || req.body?.message;
    if (!smsContent) {
      return res.status(400).send("Missing 'content' in request body");
    }

    const result = decryptSmsPayload(smsContent);

    console.log("Decrypted SMS:", result);

    // TODO: write to DB later
    res.status(200).json({
      status: "ok",
      group: result.groupNumber,
      decryptedMessage: result.message,
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Decryption failed");
  }
})
