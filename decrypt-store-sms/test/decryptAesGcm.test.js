const { decryptAesGcm, deriveAesKey } = require('../production/index');
const crypto = require('crypto');

describe('decryptAesGcm', () => {
  beforeAll(() => {
    process.env.SHARED_SECRET = "test-secret";
  });

  test('decrypts valid AES-GCM ciphertext', () => {
    const key = deriveAesKey(process.env.SHARED_SECRET, 'GROUP1');

    // Create sample plaintext
    const plaintext = Buffer.from('Hello world!', 'utf8');

    // Encrypt
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const combined = Buffer.concat([iv, encrypted, tag]);
    const base64Cipher = combined.toString('base64');

    // Decrypt
    const decrypted = decryptAesGcm(base64Cipher, key);
    expect(decrypted).toBe('Hello world!');
  });

  test('returns null for invalid tag', () => {
    const key = deriveAesKey(process.env.SHARED_SECRET, 'GROUP1');
    const base64Cipher = Buffer.from('12345678901234567890123456789012').toString('base64');
    const decrypted = decryptAesGcm(base64Cipher, key);
    expect(decrypted).toBeNull();
  });
});
