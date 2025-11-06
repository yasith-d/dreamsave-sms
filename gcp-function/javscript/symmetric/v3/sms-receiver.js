const functions = require('@google-cloud/functions-framework');
const crypto = require("crypto");

// --- CONFIG ---
const SHARED_SECRET = "Jd82jD92kd83nS91xP72rM41vQ85tL63"; // must match app
const WEBHOOK_SECRET = "2249FT7QPNM9KX6CUE3GCZQN9ALERWNZ"; // from Telerivet

// --- FUNCTION ENTRYPOINT ---
functions.http('receiveSMS', async (req, res) => {
  try {
    // Step 1: Validate webhook secret from Telerivet
    if (req.body.secret !== WEBHOOK_SECRET) {
      console.error("Unauthorized: Invalid webhook secret");
      return res.status(403).send("Forbidden");
    }

    const message = req.body.content; // Expect: "dreamstart:LK-123-456:<encrypted>"
    console.log("Incoming message:", message);

    // Step 2: Parse SMS parts
    const parts = message.split(":");
    if (parts.length < 3 || parts[0] !== "dreamstart") {
      console.error("Invalid message format");
      return res.status(400).send("Invalid message format");
    }

    const groupNumber = parts[1];
    const encryptedBase64 = parts.slice(2).join(":");

    // Step 3: Derive AES key (must match Java logic exactly)
    const hmac = crypto.createHmac("sha256", SHARED_SECRET);
    hmac.update(groupNumber);
    const base64Url = hmac.digest("base64url").substring(0, 32); // Java: substring(0, 32)
    const key = Buffer.from(base64Url, "utf8"); // use UTF-8 bytes of string

    // Step 4: Decrypt message
    const decipher = crypto.createDecipheriv("aes-256-ecb", key, null);
    let decrypted = decipher.update(encryptedBase64, "base64", "utf8");
    decrypted += decipher.final("utf8");

    console.log("Decrypted message:", decrypted);

    // Step 5: Respond or store
    return res.status(200).json({
      success: true,
      groupNumber,
      decryptedMessage: decrypted,
    });

  } catch (err) {
    console.error("Decryption failed:", err);
    return res.status(500).send("Internal Server Error");
  }
});
