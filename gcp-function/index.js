const functions = require('@google-cloud/functions-framework');
const crypto = require("crypto");
const { Pool } = require("pg");

const SHARED_SECRET = process.env.SHARED_SECRET;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

// --- DB connection ---
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 5432,
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

// === Key derivation ===
function deriveAesKey(sharedSecret, groupNumber) {
    const hmac = crypto.createHmac("sha256", sharedSecret);
    hmac.update(groupNumber);
    return hmac.digest();
}

// === Save failed decrypt attempts ===
async function saveFailedDecryptToDb(data) {
    const client = await pool.connect();
    try {
        const query = `
            INSERT INTO sms_failed_decrypt_log (
                from_number,
                to_dsl_number,
                encrypted_payload,
                raw_sms,
                error_reason
            )
            VALUES ($1, $2, $3, $4, $5);
        `;

        await client.query(query, [
            data.fromNumber,
            data.toDslNumber,
            data.encrypted,
            data.rawSms,
            data.reason
        ]);

    } catch (err) {
        console.error("Failed to save failed decrypt log:", err);
    } finally {
        client.release();
    }
}

// === AES-GCM decrypt ===
// base64Input = Base64( iv || ciphertext+tag )
function decryptAesGcm(base64Input, keyBytes) {
    const combined = Buffer.from(base64Input, "base64");
    const ivSize = 12;

    if (combined.length < ivSize + 16) {
        return null;
    }

    const iv = combined.subarray(0, ivSize);
    const cipherText = combined.subarray(ivSize);

    try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", keyBytes, iv);
        const tag = cipherText.subarray(cipherText.length - 16);
        const actualCipher = cipherText.subarray(0, cipherText.length - 16);

        decipher.setAuthTag(tag);

        const decrypted = Buffer.concat([
            decipher.update(actualCipher),
            decipher.final()
        ]);

        return decrypted.toString("utf8");

    } catch (err) {
        console.error("AES-GCM auth/tag failure:", err.message);
        return null;
    }
}

// === Parse SMS ===
function parseSms(smsContent) {
    const parts = smsContent.split(":");
    if (parts.length < 4) throw new Error("Invalid sms content format");

    if (parts[0].toLowerCase() !== "dreamstart") {
        throw new Error("Invalid tag");
    }

    const groupNumber = parts[1];
    const meetingNumber = parts[2];
    const base64Cipher = parts.slice(3).join(":");

    const keyBytes = deriveAesKey(SHARED_SECRET, groupNumber);
    const decrypted = decryptAesGcm(base64Cipher, keyBytes);

    if (!decrypted) {
        throw new Error("GCM decryption failed");
    }

    const payload = JSON.parse(decrypted);

    if (payload.meeting_number !== meetingNumber) {
        throw new Error("Tampered meeting number");
    }

    return {
        groupNumber,
        meetingNumber,
        decrypted,
        encrypted: base64Cipher,
        raw: smsContent
    };
}

// === Save to DB ===
async function saveMessageToDb({ groupNumber, meetingNumber, decrypted, encrypted, raw, country }) {
    const client = await pool.connect();
    try {
        const payload = JSON.parse(decrypted);

        const meetingTime = payload.meeting_time
            ? new Date(payload.meeting_time)
            : null;

        const cycleId = payload.cycle_id || null;
        const version = payload.version || null;

        const query = `
            INSERT INTO sms_meeting_log (
                group_number,
                meeting_number,
                meeting_time,
                cycle_id,
                version,
                encrypted_payload,
                decrypted_message,
                raw_sms,
                country
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (group_number, cycle_id, meeting_number)
            DO NOTHING;
        `;

        await client.query(query, [
            groupNumber,
            meetingNumber,
            meetingTime,
            cycleId,
            version,
            encrypted,
            decrypted,
            raw,
            country
        ]);

    } finally {
        client.release();
    }
}

// === Entry point ===
functions.http('decryptSMS', async (req, res) => {
    const fromNumber = req.body?.from_number || req.body?.from || null;
    const toDslNumber = req.body?.to_number || null;
    const rawSms = req.body?.content || req.body?.message || null;
    const country = req.body?.phone?.country || null;

    try {
        const providedSecret = req.body?.secret || req.headers["x-webhook-secret"];
        if (!providedSecret || providedSecret !== WEBHOOK_SECRET) {
            console.warn("Unauthorized request");
            return res.status(403).send("Forbidden");
        }

        if (!rawSms) {
            return res.status(400).send("Missing 'content'");
        }

        const parsed = parseSms(rawSms);

        console.log("Valid Meeting-Ended SMS received:");
        console.log(parsed);

        await saveMessageToDb({
            ...parsed,
            country
        });

        return res.status(200).json({
            status: "ok",
            group: parsed.groupNumber,
            meeting: parsed.meetingNumber,
            decryptedMessage: parsed.decrypted
        });

    } catch (err) {
        console.error("Error in decryptSMS:", err.message);

        await saveFailedDecryptToDb({
            fromNumber: fromNumber || "unknown",
            toDslNumber: toDslNumber || "unknown",
            encrypted: rawSms,
            rawSms: rawSms,
            reason: err.message || "Unknown error"
        });

        return res.status(400).json({
            status: "failed",
            reason: err.message || "Decryption failed"
        });
    }
});
