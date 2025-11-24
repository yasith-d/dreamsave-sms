const { deriveAesKey } = require('../production/index');

describe('deriveAesKey', () => {
  beforeAll(() => {
    process.env.SHARED_SECRET = "test-secret";
  });

  test('generates consistent 32-byte key', () => {
    const key1 = deriveAesKey(process.env.SHARED_SECRET, 'GROUP1');
    const key2 = deriveAesKey(process.env.SHARED_SECRET, 'GROUP1');
    expect(key1).toEqual(key2);
    expect(key1.length).toBe(32);
  });

  test('different group numbers generate different keys', () => {
    const key1 = deriveAesKey(process.env.SHARED_SECRET, 'GROUP1');
    const key2 = deriveAesKey(process.env.SHARED_SECRET, 'GROUP2');
    expect(key1.equals(key2)).toBe(false);
  });
});
