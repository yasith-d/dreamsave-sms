const crypto = require("crypto");
const { decryptAesGcm } = require("../production/index");

describe("decryptAesGcm", () => {
  test("decrypts valid AES-GCM ciphertext", () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    const plaintext = "hello world";

    let encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final()
    ]);

    const tag = cipher.getAuthTag();
    const combined = Buffer.concat([iv, encrypted, tag]).toString("base64");

    const decrypted = decryptAesGcm(combined, key);

    expect(decrypted).toBe(plaintext);
  });

  test("returns null for invalid tag", () => {
    const result = decryptAesGcm("abcd", crypto.randomBytes(32));
    expect(result).toBeNull();
  });
});
