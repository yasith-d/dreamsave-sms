const functions = require('@google-cloud/functions-framework');
const crypto = require('crypto');
const { Pool } = require('pg');

const AUDIT_SMS_KEY = process.env.AUDIT_SMS_KEY;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

// Generate AES key from root AUDIT_SMS_KEY
function deriveAesKeyFromAuditSmsKey(auditSmsKey) {
  const hmac = crypto.createHmac('sha256', Buffer.from(auditSmsKey, 'utf8'));
  return hmac.digest();
}

// Attempt AES-GCM decryption of the encrypted payload
function decryptAesGcm(base64Input, keyBytes) {
  let combined;
  try { combined = Buffer.from(base64Input, 'base64'); } 
  catch (e) { console.error('Base64 decode failed', e.message); return null; }

  const ivSize = 12;
  if (combined.length < ivSize + 16) { console.error('Combined length too small for iv + tag'); return null; }

  const iv = combined.subarray(0, ivSize);
  const cipherText = combined.subarray(ivSize);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes, iv);
    const tag = cipherText.subarray(cipherText.length - 16);
    const actualCipher = cipherText.subarray(0, cipherText.length - 16);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(actualCipher), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) { console.error('AES-GCM auth/tag failure:', err.message); return null; }
}

// Save raw SMS into failed decrypt table
async function saveFailedDecryptToDb(data) {
  const client = await pool.connect();
  try {
    const query = `
      INSERT INTO sms_failed_decrypt_log (
        from_number, to_dsl_number, raw_sms, error_reason
      ) VALUES ($1,$2,$3,$4)
    `;
    await client.query(query, [
      data.fromNumber || "unknown",
      data.toDslNumber || "unknown",
      data.rawSms || "unknown",
      data.reason || "unknown"
    ]);
  } catch (err) { console.error('Failed to save failed decrypt log:', err); } 
  finally { client.release(); }
}

// Parse DS:encrypted payload from raw SMS
function parseDsSms(rawSms, auditSmsKey) {
  if (!rawSms) throw new Error("Empty SMS content");
  const idx = rawSms.indexOf(":");
  if (idx === -1) throw new Error("Invalid SMS format: missing ':'");
  const tag = rawSms.substring(0, idx).trim().toLowerCase();
  if (tag !== "ds") throw new Error("Invalid tag: expected 'DS'");
  const encryptedPart = rawSms.substring(idx + 1).trim();
  if (!encryptedPart) throw new Error("Empty DS encrypted payload");

  const keyBytes = deriveAesKeyFromAuditSmsKey(auditSmsKey);
  const decrypted = decryptAesGcm(encryptedPart, keyBytes);
  if (!decrypted) throw new Error("Decryption failed: invalid encrypted payload");

  const parts = decrypted.split(",").map(p => p.trim());
  if (parts.length !== 4) throw new Error(`Invalid decrypted payload: expected 4 CSV fields, got ${parts.length}`);
  const [groupId, meetingId, versionInt, timestamp] = parts;
  if (!groupId || !meetingId || !versionInt || !timestamp) throw new Error("Invalid DS payload: one or more fields are empty");

  return buildParsedResult({
    groupId,
    meetingId,
    versionRaw: versionInt,
    timestampRaw: timestamp,
    decryptedString: decrypted,
    encryptedPayloadRaw: encryptedPart,
    wasEncrypted: true
  });
}

// Build the parsed output object
function buildParsedResult({ groupId, meetingId, versionRaw, timestampRaw, decryptedString, encryptedPayloadRaw, wasEncrypted }) {
  const versionString = convertVersionIntToDotted(versionRaw) || "unknown";
  const meetingTime = (timestampRaw && !isNaN(Number(timestampRaw))) ? Number(timestampRaw) : 0;

  return {
    groupId: groupId || "unknown",
    meetingId: meetingId || "unknown",
    version: versionString,
    meetingTime,
    decrypted: decryptedString || "unknown",
    encrypted: encryptedPayloadRaw || "unknown",
    wasEncrypted: !!wasEncrypted
  };
}

// Convert integer app version to dotted notation
function convertVersionIntToDotted(v) {
  if (v === null || v === undefined) return "unknown";
  const s = String(v).trim();
  if (s.length === 3) return `${s[0]}.${s[1]}.${s[2]}`;
  if (s.length === 4) return `${s[0]}.${s.slice(1, 3)}.${s[3]}`;
  return s;
}

// Save decrypted SMS into main sms_meeting_log table
async function saveMessageToDb({ groupId, meetingId, meetingTime, version, encrypted, decrypted, raw, country, fromNumber, toDslNumber }) {
  const client = await pool.connect();
  try {
    const query = `
      INSERT INTO sms_meeting_log (meeting_id, group_id, meeting_time, version, encrypted_payload,
        decrypted_message, raw_sms, country, from_number, to_dsl_number
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      ON CONFLICT (meeting_id) DO NOTHING;
    `;
    await client.query(query, [
      meetingId || "unknown",
      groupId || "unknown",
      meetingTime || 0,
      version || "unknown",
      encrypted || "unknown",
      decrypted || "unknown",
      raw || "unknown",
      country || "unknown",
      fromNumber || "unknown",
      toDslNumber || "unknown"
    ]);
  } finally { client.release(); }
}

// === Entry point ===
functions.http('decryptSMS', async (req, res) => {
  const fromNumber = req.body?.from_number || req.body?.from || "unknown";
  const toDslNumber = req.body?.to_number || "unknown";
  const rawSms = req.body?.content || req.body?.message || "unknown";
  const country = req.body?.phone?.country || "unknown";

  try {
    const providedSecret = req.body?.secret || req.headers['x-webhook-secret'];
    if (!providedSecret || providedSecret !== WEBHOOK_SECRET) return res.status(403).send('Forbidden');

    if (!rawSms) return res.status(400).send("Missing 'content'");

    const parsed = parseDsSms(rawSms, AUDIT_SMS_KEY);

    await saveMessageToDb({
      groupId: parsed.groupId,
      meetingId: parsed.meetingId,
      meetingTime: parsed.meetingTime,
      version: parsed.version,
      encrypted: parsed.encrypted,
      decrypted: parsed.decrypted,
      raw: rawSms,
      country,
      fromNumber,
      toDslNumber
    });

    console.log(`[SUCCESS] DSL SMS decrypted | meetingId=${parsed.meetingId} | groupId=${parsed.groupId}`);

    return res.status(200).json({
      status: 'ok',
      group: parsed.groupId,
      meeting: parsed.meetingId,
      decryptedMessage: parsed.decrypted
    });
  } catch (err) {
    console.log(`[FAILED] DSL SMS decrypt failed | from=${fromNumber} | err=${err.message}`);

    await saveFailedDecryptToDb({
      fromNumber,
      toDslNumber,
      rawSms,
      reason: err.message || "unknown"
    });

    // Telerivet will repeatedly call the webhook until any 2xx status received
    // Therefore responding with any other code will cause duplicate failed decryption entries to be formed in DB
    return res.status(201).json({
      status: 'failed',
      reason: err.message || 'Decryption failed'
    });
  }
});

// For unit tests
module.exports = {
  deriveAesKeyFromAuditSmsKey,
  decryptAesGcm,
  parseDsSms
};
