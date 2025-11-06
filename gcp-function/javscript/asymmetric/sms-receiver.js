/**
 * Telerivet Webhook Receiver for DreamSave SMS Tracking
 * ---------------------------------------
 * 1. Verifies webhook secret from Telerivet
 * 2. Parses and decrypts encrypted message content
 * 3. Logs or stores decrypted message for testing
 */

import crypto from "crypto";

// Decrypt using RSA private key (same one paired with frontend public key)
function decryptMessage(encryptedBase64) {
  const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, "\n");
  const buffer = Buffer.from(encryptedBase64, "base64");

  const decrypted = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    },
    buffer
  );

  return decrypted.toString("utf8");
}

// Main Cloud Function
export async function receiveSms(req, res) {
  try {
    const { secret, content, from_number, to_number, time_created } = req.body;
    const TELERIVET_SECRET = process.env.TELERIVET_SECRET;

    // 1️⃣ Verify Telerivet secret
    if (secret !== TELERIVET_SECRET) {
      console.error("Invalid Telerivet secret");
      return res.status(403).send("Forbidden");
    }

    // 2️⃣ Parse message
    // Example content: dreamstart:LK-123-456:ENCRYPTED_BASE64
    const parts = content.split(":");
    if (parts.length < 3) {
      console.error("Malformed message:", content);
      return res.status(400).send("Malformed message");
    }

    const tag = parts[0];
    const groupNumber = parts[1];
    const encryptedPayload = parts.slice(2).join(":"); // handle if ":" exists in payload

    // 3️⃣ Decrypt
    let decryptedText = "";
    try {
      decryptedText = decryptMessage(encryptedPayload);
    } catch (err) {
      console.error("Decryption failed:", err);
      decryptedText = "(decryption failed)";
    }

    // 4️⃣ Log or save
    console.log("✅ Incoming SMS from Telerivet");
    console.log("Tag:", tag);
    console.log("Group Number:", groupNumber);
    console.log("From:", from_number);
    console.log("To:", to_number);
    console.log("Time:", time_created);
    console.log("Decrypted Message:", decryptedText);

    // TODO: optional - insert into Firestore, Cloud SQL, etc.

    res.status(200).send("OK");
  } catch (err) {
    console.error("Error processing SMS:", err);
    res.status(500).send("Server error");
  }
}
