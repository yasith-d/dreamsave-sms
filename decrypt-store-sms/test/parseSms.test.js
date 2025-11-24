// parseSms.test.js
process.env.SHARED_SECRET = "test-secret"; // MUST be BEFORE require
const { parseSms, deriveAesKey, decryptAesGcm } = require('../production/index');
const crypto = require('crypto');

describe('parseSms', () => {
  test('parses and decrypts a valid SMS', () => {
    const groupNumber = 'GROUP1';
    const meetingNumber = 'M#1';
    const plaintextPayload = JSON.stringify({ id: '1234', n: meetingNumber, t: Date.now() });

    const key = deriveAesKey(process.env.SHARED_SECRET, groupNumber);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintextPayload, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    const combined = Buffer.concat([iv, encrypted, tag]);
    const base64Cipher = combined.toString('base64');

    const smsContent = `DreamStart:${groupNumber}:${meetingNumber}:${base64Cipher}`;
    const parsed = parseSms(smsContent);

    expect(parsed.groupNumber).toBe(groupNumber);
    expect(parsed.meetingNumber).toBe(meetingNumber);
    expect(parsed.meetingId).toBe('1234');
    expect(parsed.decrypted).toBe(plaintextPayload);
  });

  test('throws for invalid tag', () => {
    const smsContent = 'WRONGTAG:GROUP1:M#1:abcdef';
    expect(() => parseSms(smsContent)).toThrow('Invalid tag');
  });
});
