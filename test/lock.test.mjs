// App-lock vault crypto: the circle secret must be unrecoverable from the
// on-disk record without the passcode, and a wrong passcode must fail closed.
import test from "node:test";
import assert from "node:assert/strict";

import {
  makePasscodeRecord,
  openPasscodeRecord,
  sealUnderVault,
  openUnderVault,
  newVaultKey,
  PBKDF2_ITERS,
  ARGON2_PARAMS,
  passcodeNeedsRewrap,
  zero,
  randomBytes,
} from "../app/js/lock.js";

const SECRET = Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 3) & 0xff);

test("passcode record round-trips the exact secret", async () => {
  const rec = await makePasscodeRecord("correct horse battery", SECRET);
  const back = await openPasscodeRecord(rec, "correct horse battery");
  assert.ok(back);
  assert.deepEqual([...back], [...SECRET]);
});

test("record carries no plaintext secret and a real KDF cost", async () => {
  const rec = await makePasscodeRecord("pw", SECRET);
  assert.equal(rec.kdf, "argon2id");
  assert.equal(rec.v, 2);
  assert.deepEqual({ t: rec.t, m: rec.m, p: rec.p }, { ...ARGON2_PARAMS });
  assert.ok(rec.m >= 19456 && rec.t >= 2, "OWASP floor for Argon2id");
  assert.equal(rec.iters, undefined);
  assert.equal(rec.salt.length, 16);
  assert.equal(rec.nonce.length, 12);
  assert.equal(rec.ct.length, 48); // 32 secret + 16 GCM tag
  // The secret bytes must not appear anywhere in the serialized record.
  const hay = [...rec.salt, ...rec.nonce, ...rec.ct].join(",");
  const needle = [...SECRET].join(",");
  assert.ok(!hay.includes(needle), "secret must not be recoverable from the record");
});

test("wrong passcode returns null, never throws, never leaks", async () => {
  const rec = await makePasscodeRecord("right", SECRET);
  for (const bad of ["", "Right", "right ", "rightt", "wrong entirely"]) {
    assert.equal(await openPasscodeRecord(rec, bad), null, `bad=${JSON.stringify(bad)}`);
  }
});

test("a flipped ciphertext or nonce byte fails authentication", async () => {
  const rec = await makePasscodeRecord("pw", SECRET);
  const tamperCt = { ...rec, ct: Uint8Array.from(rec.ct) };
  tamperCt.ct[0] ^= 1;
  assert.equal(await openPasscodeRecord(tamperCt, "pw"), null);
  const tamperNonce = { ...rec, nonce: Uint8Array.from(rec.nonce) };
  tamperNonce.nonce[0] ^= 1;
  assert.equal(await openPasscodeRecord(tamperNonce, "pw"), null);
});

test("each record uses a fresh salt and nonce", async () => {
  const a = await makePasscodeRecord("pw", SECRET);
  const b = await makePasscodeRecord("pw", SECRET);
  assert.notDeepEqual([...a.salt], [...b.salt]);
  assert.notDeepEqual([...a.nonce], [...b.nonce]);
  assert.notDeepEqual([...a.ct], [...b.ct]);
});

test("unknown KDF is rejected", async () => {
  const rec = await makePasscodeRecord("pw", SECRET);
  assert.equal(await openPasscodeRecord({ ...rec, kdf: "md5" }, "pw"), null);
  assert.equal(await openPasscodeRecord(null, "pw"), null);
});

test("a PBKDF2 record from before 0.16 still opens, and is flagged for re-wrap", async () => {
  const rec = await makePasscodeRecord("pw", SECRET, PBKDF2_ITERS);
  assert.equal(rec.kdf, "pbkdf2-sha256");
  assert.equal(rec.iters, PBKDF2_ITERS);
  const back = await openPasscodeRecord(rec, "pw");
  assert.deepEqual([...back], [...SECRET]);
  assert.equal(await openPasscodeRecord(rec, "pw "), null);
  assert.equal(passcodeNeedsRewrap(rec), true);
  const fresh = await makePasscodeRecord("pw", back);
  assert.equal(passcodeNeedsRewrap(fresh), false);
  assert.deepEqual([...(await openPasscodeRecord(fresh, "pw"))], [...SECRET], "the re-wrapped record opens to the same K");
  assert.equal(passcodeNeedsRewrap(null), false);
});

test("an Argon2id record below today's cost is flagged, one at it is not", async () => {
  const weak = await makePasscodeRecord("pw", SECRET, { t: 1, m: 8192, p: 1 });
  assert.equal(weak.kdf, "argon2id");
  assert.equal(passcodeNeedsRewrap(weak), true);
  assert.deepEqual([...(await openPasscodeRecord(weak, "pw"))], [...SECRET], "weak but genuine records still open");
  assert.equal(passcodeNeedsRewrap({ ...weak, t: ARGON2_PARAMS.t, m: ARGON2_PARAMS.m }), false);
});

test("tampered Argon2id parameters fail closed without allocating", async () => {
  const rec = await makePasscodeRecord("pw", SECRET, { t: 1, m: 8192, p: 1 });
  for (const bad of [
    { m: 2 ** 30 },
    { m: 0 },
    { t: 0 },
    { t: 1000 },
    { p: 64 },
    { m: "8192" },
    { salt: "not bytes" },
  ]) {
    assert.equal(await openPasscodeRecord({ ...rec, ...bad }, "pw"), null, JSON.stringify(bad));
  }
  await assert.rejects(makePasscodeRecord("pw", SECRET, { t: 1, m: 2 ** 30, p: 1 }), RangeError);
});

test("zero scrubs a buffer", () => {
  const b = randomBytes(16);
  zero(b);
  assert.deepEqual([...b], new Array(16).fill(0));
});

// -------------------------------------------------- vault-key model

test("secret round-trips when sealed under the vault key", async () => {
  const K = newVaultKey();
  const sealed = await sealUnderVault(K, SECRET);
  const back = await openUnderVault(K, sealed);
  assert.ok(back);
  assert.deepEqual([...back], [...SECRET]);
});

test("a different vault key cannot open the sealed secret", async () => {
  const K = newVaultKey();
  const sealed = await sealUnderVault(K, SECRET);
  assert.equal(await openUnderVault(newVaultKey(), sealed), null);
});

test("full lock lifecycle: enable, lock, unlock, change passcode, rotate", async () => {
  // Enable: make a vault key, wrap it with the passcode, seal the secret.
  const K = newVaultKey();
  const passRec = await makePasscodeRecord("1234", K);
  let sealed = await sealUnderVault(K, SECRET);

  // A fresh boot only has passRec + sealed on disk. Unlock with the passcode.
  const K2 = await openPasscodeRecord(passRec, "1234");
  assert.ok(K2, "correct passcode recovers the vault key");
  const secret = await openUnderVault(K2, sealed);
  assert.deepEqual([...secret], [...SECRET], "vault key decrypts the secret");
  assert.equal(await openPasscodeRecord(passRec, "0000"), null, "wrong passcode fails");

  // Change passcode: re-wrap the SAME K, secret untouched.
  const passRec2 = await makePasscodeRecord("5678", K2);
  assert.equal(await openPasscodeRecord(passRec2, "1234"), null, "old passcode no longer opens");
  const K3 = await openPasscodeRecord(passRec2, "5678");
  assert.deepEqual([...(await openUnderVault(K3, sealed))], [...SECRET], "secret still decrypts after passcode change");

  // Rotate the circle: re-seal a new secret under the same K, no passcode needed.
  const NEW = randomBytes(32);
  sealed = await sealUnderVault(K3, NEW);
  assert.deepEqual([...(await openUnderVault(K3, sealed))], [...NEW]);
  assert.notDeepEqual([...(await openUnderVault(K3, sealed))], [...SECRET]);
});

test("disk records leak neither the vault key nor the secret", async () => {
  const K = newVaultKey();
  const passRec = await makePasscodeRecord("pw", K);
  const sealed = await sealUnderVault(K, SECRET);
  const disk = [...passRec.salt, ...passRec.nonce, ...passRec.ct, ...sealed.nonce, ...sealed.ct].join(",");
  assert.ok(!disk.includes([...K].join(",")), "vault key must not be on disk in the clear");
  assert.ok(!disk.includes([...SECRET].join(",")), "secret must not be on disk in the clear");
});
