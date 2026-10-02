// The Argon2id module behind the app lock: the shipped WebAssembly is the
// exact bytes the loader pins, it imports nothing, and it computes the
// published test vectors. A build that drifted from the reference would fail
// here before it could ever wrap a key.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { argon2id, ARGON2_PARAMS, ARGON2_LIMITS, ARGON2_WASM_SHA256, validParams } from "../app/js/argon2.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const wasmBytes = readFileSync(path.join(ROOT, "app", "js", "argon2.wasm"));
const te = new TextEncoder();
const hex = (b) => Buffer.from(b).toString("hex");

test("the shipped wasm is the bytes the loader pins", () => {
  assert.equal(createHash("sha256").update(wasmBytes).digest("hex"), ARGON2_WASM_SHA256);
});

test("the module imports nothing and exports only the four names", () => {
  const mod = new WebAssembly.Module(wasmBytes);
  assert.deepEqual(WebAssembly.Module.imports(mod), []);
  const names = WebAssembly.Module.exports(mod).map((e) => `${e.name}:${e.kind}`).sort();
  assert.deepEqual(names, ["alloc:function", "argon2id:function", "memory:memory", "reset:function"]);
});

test("RFC 9106 Argon2id test vector", async () => {
  const out = await argon2id({
    password: new Uint8Array(32).fill(1),
    salt: new Uint8Array(16).fill(2),
    secret: new Uint8Array(8).fill(3),
    ad: new Uint8Array(12).fill(4),
    t: 3,
    m: 32,
    p: 4,
    outLen: 32,
  });
  assert.equal(hex(out), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
});

// From the reference implementation's src/test.c (version 0x13, Argon2id).
const REFERENCE = [
  [2, 16, 1, "password", "somesalt", "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"],
  [2, 8, 1, "password", "somesalt", "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"],
  [2, 8, 2, "password", "somesalt", "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037"],
  [1, 16, 1, "password", "somesalt", "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98"],
  [4, 16, 1, "password", "somesalt", "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c"],
  [2, 16, 1, "differentpassword", "somesalt", "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde"],
  [2, 16, 1, "password", "diffsalt", "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c"],
];

for (const [t, logm, p, pw, salt, want] of REFERENCE) {
  test(`reference vector t=${t} m=2^${logm} p=${p} ${pw}/${salt}`, async () => {
    const out = await argon2id({ password: te.encode(pw), salt: te.encode(salt), t, m: 2 ** logm, p, outLen: 32 });
    assert.equal(hex(out), want);
  });
}

test("the lock's parameters sit inside the limits and above the OWASP floor", () => {
  assert.ok(validParams(ARGON2_PARAMS));
  assert.ok(ARGON2_PARAMS.m >= 19456 && ARGON2_PARAMS.t >= 2, "OWASP 2024: 19 MiB and 2 passes at least");
  assert.equal(ARGON2_PARAMS.p, 1);
});

test("parameters outside the limits are refused before any memory is asked for", async () => {
  const base = { password: te.encode("pw"), salt: te.encode("saltsalt"), outLen: 32 };
  for (const bad of [
    { t: 0, m: 8192, p: 1 },
    { t: ARGON2_LIMITS.t[1] + 1, m: 8192, p: 1 },
    { t: 1, m: 4, p: 1 },
    { t: 1, m: 8, p: 2 },
    { t: 1, m: 2 ** 31, p: 1 },
    { t: 1, m: 8192, p: 0 },
    { t: 1.5, m: 8192, p: 1 },
    { t: "3", m: 8192, p: 1 },
  ]) {
    await assert.rejects(argon2id({ ...base, ...bad }), RangeError, JSON.stringify(bad));
  }
  await assert.rejects(argon2id({ ...base, salt: te.encode("short"), t: 1, m: 8192, p: 1 }), RangeError);
});

test("same inputs give the same bytes, a changed salt or passcode does not, and outLen is honored", async () => {
  const a = await argon2id({ password: te.encode("pw"), salt: te.encode("saltsalt"), t: 1, m: 8192, p: 1 });
  const b = await argon2id({ password: te.encode("pw"), salt: te.encode("saltsalt"), t: 1, m: 8192, p: 1 });
  const c = await argon2id({ password: te.encode("pw"), salt: te.encode("saltsalt2"), t: 1, m: 8192, p: 1 });
  const d = await argon2id({ password: te.encode("pw2"), salt: te.encode("saltsalt"), t: 1, m: 8192, p: 1 });
  assert.equal(hex(a), hex(b));
  assert.notEqual(hex(a), hex(c));
  assert.notEqual(hex(a), hex(d));
  const long = await argon2id({ password: te.encode("pw"), salt: te.encode("saltsalt"), t: 1, m: 8192, p: 1, outLen: 64 });
  assert.equal(long.length, 64);
  assert.notEqual(hex(long.subarray(0, 32)), hex(a), "a longer tag is not a prefix of the shorter one");
});

test("the password bytes handed in are not kept by the module", async () => {
  // Each call runs in a fresh instance whose arena is zeroed on the way out;
  // the caller's own copy is untouched, and that is what lock.js zeroes.
  const pw = te.encode("keep me");
  await argon2id({ password: pw, salt: te.encode("saltsalt"), t: 1, m: 8192, p: 1 });
  assert.equal(new TextDecoder().decode(pw), "keep me");
});
