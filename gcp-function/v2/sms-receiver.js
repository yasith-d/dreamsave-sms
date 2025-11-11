const functions = require('@google-cloud/functions-framework');
const crypto = require("crypto");

const SHARED_SECRET = "Jd82jD92kd83nS91xP72rM41vQ85tL63";
const WEBHOOK_SECRET = "2249FT7QPNM9KX6CUE3GCZQN9ALERWNZ";

functions.http('receiveSMS', async (req, res) => {
  try {
    if (req.body.secret !== WEBHOOK_SECRET) {
      console.error("Unauthorized: Invalid webhook secret");
      return res.status(403).send("Forbidden");
    }

    const message = req.body.content;
    console.log("Incoming message:", message);

    const parts = message.split(":");
    if (parts.length < 3 || parts[0] !== "dreamstart") {
      return res.status(400).send("Invalid message format");
    }

    const groupNumber = parts[1];
    const encryptedBase64 = parts.slice(2).join(":");

    // Derive AES key using raw bytes
    const hmac = crypto.createHmac("sha256", SHARED_SECRET);
    hmac.update(groupNumber);
    const key = hmac.digest().subarray(0, 32); // 32 bytes

    // Decrypt
    const decipher = crypto.createDecipheriv("aes-256-ecb", key, null);
    let decrypted = decipher.update(encryptedBase64, "base64", "utf8");
    decrypted += decipher.final("utf8");

    console.log("Decrypted message:", decrypted);

    res.status(200).json({
      success: true,
      groupNumber,
      decryptedMessage: decrypted
    });
  } catch (err) {
    console.error("Decryption failed:", err);
    res.status(500).send("Internal Server Error");
  }
});
