const crypto = require("crypto");
const { deriveAesKey, parseSms } = require("../production/index");

function encryptForTest(sharedSecret, group, payloadObj) {
  const key = deriveAesKey(sharedSecret, group);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const json = JSON.stringify(payloadObj);
  let encrypted = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, encrypted, tag]).toString("base64");
}

describe("parseSms", () => {
  const SHARED_SECRET = process.env.SHARED_SECRET = "test-secret";

  test("parses and decrypts a valid SMS", () => {
    const enc = encryptForTest(SHARED_SECRET, "G100", { id: "M1", n: "5" });

    const sms = `DreamStart:G100:5:${enc}`;
    const parsed = parseSms(sms);

    expect(parsed.groupNumber).toBe("G100");
    expect(parsed.meetingNumber).toBe("5");
    expect(parsed.meetingId).toBe("M1");
  });

  test("throws for invalid tag", () => {
    expect(() => parseSms("Wrong:123:5:xyz")).toThrow("Invalid tag");
  });
});
