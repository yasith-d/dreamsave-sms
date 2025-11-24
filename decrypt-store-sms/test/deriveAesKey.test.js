const { deriveAesKey } = require("../production/index");

describe("deriveAesKey", () => {
  test("generates consistent 32-byte key", () => {
    const key1 = deriveAesKey("shared-secret", "G12345");
    const key2 = deriveAesKey("shared-secret", "G12345");

    expect(key1.length).toBe(32);
    expect(key1.equals(key2)).toBe(true);
  });

  test("different group numbers generate different keys", () => {
    const key1 = deriveAesKey("secret", "G1");
    const key2 = deriveAesKey("secret", "G2");

    expect(key1.equals(key2)).toBe(false);
  });
});
