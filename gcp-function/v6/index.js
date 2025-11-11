const functions = require('@google-cloud/functions-framework');
const crypto = require("crypto");
const { Pool } = require("pg");

const SHARED_SECRET = process.env.SHARED_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// DB connection
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

function deriveAesKey(sharedSecret, groupNumber) {
  const hmac = crypto.createHmac("sha256", sharedSecret);
  hmac.update(groupNumber);
  return hmac.digest();
}

function decryptAesEcb(base64CipherText, keyBytes) {
  const decipher = crypto.createDecipheriv("aes-256-ecb", keyBytes, null);
  decipher.setAutoPadding(true);
  const encrypted = Buffer.from(base64CipherText, "base64");
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
}

function parseSms(smsContent) {
  const parts = smsContent.split(":");
  if (parts.length < 4) throw new Error("Invalid sms content format");
  if (parts[0] !== "dreamstart") throw new Error("Invalid tag");

  const groupId = parts[1];
  const meetingId = parts[2];
  const base64 = parts.slice(3).join(":");
  const keyBytes = deriveAesKey(SHARED_SECRET, groupId);
  const decrypted = decryptAesEcb(base64, keyBytes);

  return { groupId, meetingId, decrypted, encrypted: base64, raw: smsContent };
}

async function saveMessageToDb({ groupId, meetingId, decrypted, encrypted, raw }) {
  const client = await pool.connect();
  try {
    const payload = JSON.parse(decrypted);
    const meetingEndedAt = payload.endedAt ? new Date(payload.endedAt) : null;

    const query = `
      INSERT INTO sms_meeting_log (
        group_id, meeting_id, meeting_ended_at,
        encrypted_payload, decrypted_message, raw_sms
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (group_id, meeting_id)
      DO UPDATE
      SET meeting_ended_at = EXCLUDED.meeting_ended_at,
          encrypted_payload = EXCLUDED.encrypted_payload,
          decrypted_message = EXCLUDED.decrypted_message,
          raw_sms = EXCLUDED.raw_sms,
          updated_at = NOW();
    `;
    await client.query(query, [
      groupId,
      meetingId,
      meetingEndedAt,
      encrypted,
      decrypted,
      raw,
    ]);
  } finally {
    client.release();
  }
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
    if (!smsContent) return res.status(400).send("Missing 'content'");

    const parsed = parseSms(smsContent);
    console.log("Decrypted SMS:", parsed);

    await saveMessageToDb(parsed);

    res.status(200).json({
      status: "ok",
      group: parsed.groupId,
      meeting: parsed.meetingId,
      decryptedMessage: parsed.decrypted,
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("Decryption or DB write failed");
  }
});
