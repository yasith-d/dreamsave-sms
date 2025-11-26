const functions = require('@google-cloud/functions-framework');
const crypto = require('crypto');
const { Pool } = require('pg');

const SHARED_SECRET = process.env.SHARED_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// === DB connection ===
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

// === Key derivation ===
// returns Buffer (32 bytes for HmacSHA256)
function deriveAesKeyFromSharedSecret(sharedSecret) {
  const hmac = crypto.createHmac('sha256', Buffer.from(sharedSecret, 'utf8'));
  return hmac.digest();
}

// === AES-GCM decrypt ===
// base64Input = Base64( iv(12) + ciphertext + tag(16) )
function decryptAesGcm(base64Input, keyBytes) {
  let combined;
  try {
    combined = Buffer.from(base64Input, 'base64');
  } catch (e) {
    console.error('Base64 decode failed', e.message);
    return null;
  }
  const ivSize = 12;
  if (combined.length < ivSize + 16) {
    console.error('Combined length too small for iv + tag');
    return null;
  }

  const iv = combined.subarray(0, ivSize);
  const cipherText = combined.subarray(ivSize);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBytes, iv);
    const tag = cipherText.subarray(cipherText.length - 16);
    const actualCipher = cipherText.subarray(0, cipherText.length - 16);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(actualCipher), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err) {
    console.error('AES-GCM auth/tag failure:', err.message);
    return null;
  }
}

// === Save failed decrypt attempts ===
async function saveFailedDecryptToDb(data) {
  const client = await pool.connect();
  try {
    const query = `
      INSERT INTO sms_failed_decrypt_log (
        from_number, to_dsl_number, encrypted_payload, raw_sms, error_reason
      ) VALUES ($1,$2,$3,$4,$5)
    `;
    await client.query(query, [
      data.fromNumber || null,
      data.toDslNumber || null,
      data.encrypted || null,
      data.rawSms || null,
      data.reason || null
    ]);
  } catch (err) {
    console.error('Failed to save failed decrypt log:', err);
  } finally {
    client.release();
  }
}

// === Parse the DS SMS body ===
// Strict: expect DS:<base64(iv+ciphertext+tag)>
function parseDsSms(rawSms, sharedSecret) {
  if (!rawSms) throw new Error("Empty SMS content");

  // Must contain DS:<payload>
  const idx = rawSms.indexOf(":");
  if (idx === -1) throw new Error("Invalid SMS format: missing ':'");

  const tag = rawSms.substring(0, idx).trim().toLowerCase();
  if (tag !== "ds") throw new Error("Invalid tag: expected 'DS'");

  const encryptedPart = rawSms.substring(idx + 1).trim();
  if (!encryptedPart) throw new Error("Empty DS encrypted payload");

  // Derive AES key
  const keyBytes = deriveAesKeyFromSharedSecret(sharedSecret);

  // Try to decrypt
  const decrypted = decryptAesGcm(encryptedPart, keyBytes);
  if (!decrypted) {
    throw new Error("Decryption failed: invalid encrypted payload");
  }

  // Split into 4 CSV fields exactly
  const parts = decrypted.split(",").map(p => p.trim());
  if (parts.length !== 4) {
    throw new Error(`Invalid decrypted payload: expected 4 CSV fields, got ${parts.length}`);
  }

  const [groupId, meetingId, versionInt, timestamp] = parts;

  if (!groupId || !meetingId || !versionInt || !timestamp) {
    throw new Error("Invalid DS payload: one or more fields are empty");
  }

  // Build the canonical parsed object using your existing builder
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

function buildParsedResult({ groupId, meetingId, versionRaw, timestampRaw, decryptedString, encryptedPayloadRaw, wasEncrypted }) {
  const versionString = convertVersionIntToDotted(versionRaw);

  let meetingTime = null;
  if (timestampRaw) {
    const tsNum = Number(timestampRaw);
    if (!Number.isNaN(tsNum) && tsNum > 0) {
      meetingTime = new Date(tsNum * 1000);
    }
  }

  return {
    groupId,
    meetingId,
    version: versionString,
    meetingTime,
    decrypted: decryptedString,
    encrypted: encryptedPayloadRaw,
    wasEncrypted: !!wasEncrypted
  };
}

// === Convert version int to dotted notation ===
function convertVersionIntToDotted(v) {
  if (v === null || v === undefined) return null;

  const s = String(v).trim();
  if (!/^\d+$/.test(s)) return s; // return as-is if not numeric

  if (s.length === 3) { // x.x.x
    return `${s[0]}.${s[1]}.${s[2]}`;
  }

  if (s.length === 4) { // x.xx.x
    return `${s[0]}.${s.slice(1, 3)}.${s[3]}`;
  }

  // if other lengths appear, return raw
  return s;
}

// === Save parsed message to DB ===
async function saveMessageToDb({ groupId, meetingId, meetingTime, version, encrypted, decrypted, raw, country, fromNumber, toDslNumber }) {
  const client = await pool.connect();
  try {
    const query = `
      INSERT INTO sms_meeting_log (
        meeting_id,
        group_id,
        meeting_time,
        version,
        encrypted_payload,
        decrypted_message,
        raw_sms,
        country,
        from_number,
        to_dsl_number
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
      ON CONFLICT (meeting_id) DO NOTHING;
    `;
    await client.query(query, [
      meetingId,
      groupId,
      meetingTime,
      version,
      encrypted,
      decrypted,
      raw,
      country,
      fromNumber,
      toDslNumber
    ]);
  } finally {
    client.release();
  }
}

// === Entry point ===
functions.http('decryptSMS', async (req, res) => {
  const fromNumber = req.body?.from_number || req.body?.from || "unknown";
  const toDslNumber = req.body?.to_number || "unknown";
  const rawSms = req.body?.content || req.body?.message || null;
  const country = req.body?.phone?.country || null;

  try {
    const providedSecret = req.body?.secret || req.headers['x-webhook-secret'];
    if (!providedSecret || providedSecret !== WEBHOOK_SECRET) {
      console.warn('Unauthorized request');
      return res.status(403).send('Forbidden');
    }

    if (!rawSms) {
      return res.status(400).send("Missing 'content'");
    }

    const parsed = parseDsSms(rawSms, SHARED_SECRET);

    console.log('Valid DS Meeting-Ended SMS received:', {
      groupId: parsed.groupId,
      meetingId: parsed.meetingId,
      version: parsed.version,
      meetingTime: parsed.meetingTime,
      wasEncrypted: parsed.wasEncrypted
    });

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

    return res.status(200).json({
      status: 'ok',
      group: parsed.groupId,
      meeting: parsed.meetingId,
      decryptedMessage: parsed.decrypted
    });
  } catch (err) {
    console.error('Error in decryptSMS:', err.message || err);

    await saveFailedDecryptToDb({
      fromNumber: fromNumber || 'unknown',
      toDslNumber: toDslNumber || 'unknown',
      encrypted: rawSms,
      rawSms: rawSms,
      reason: err.message || String(err)
    });

    return res.status(400).json({
      status: 'failed',
      reason: err.message || 'Decryption failed'
    });
  }
});

// === Export helpers for unit tests ===
module.exports = {
  deriveAesKeyFromSharedSecret,
  decryptAesGcm,
  parseDsSms
};
