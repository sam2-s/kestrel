// QR decoder tests. The in-house encoder gives a python-free floor (every
// version and mask, rendered and read back). The ground truth for the rest
// is python qrcode, rendered and warped by tools/gen-qr-fixtures.py with
// Pillow and numpy, with zbarimg as an independent second reader where it is
// installed. Each distortion class is held to the pass rate the decoder
// actually reaches, so a regression shows as a number, not a feeling. A
// wrong read is worse than no read, so every non-null answer anywhere in
// the fixture set has to be the right one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { decode } from "../app/js/qrscan.js";
import { qrMatrix, qrMatrixForced } from "../app/js/qr.js";
import { checkSafetyQr, parseSafetyQr, safetyQrText } from "../app/js/roster.js";
import { generateIdentity } from "../app/js/crypto.js";
import { b64uEncode, safetyNumber } from "../app/js/wire.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const GEN = path.join(ROOT, "tools", "gen-qr-fixtures.py");

// ------------------------------------------------------------- helpers

// A module matrix drawn as 8-bit gray with a four-module quiet zone.
function render(m, scale = 3, quiet = 4) {
  const n = m.length;
  const size = (n + 2 * quiet) * scale;
  const data = new Uint8Array(size * size).fill(255);
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (!m[y][x]) continue;
      for (let yy = 0; yy < scale; yy++) {
        const row = ((y + quiet) * scale + yy) * size + (x + quiet) * scale;
        data.fill(0, row, row + scale);
      }
    }
  }
  return { width: size, height: size, data };
}

function readPgm(file) {
  const buf = readFileSync(file);
  const m = buf.toString("latin1", 0, 64).match(/^P5\s+(\d+)\s+(\d+)\s+255\s/);
  assert.ok(m, `${file} is not an 8-bit PGM`);
  const width = Number(m[1]);
  const height = Number(m[2]);
  const data = new Uint8Array(buf.buffer, buf.byteOffset + m[0].length, width * height);
  return { width, height, data };
}

// Deterministic noise, so a failure reproduces.
function lcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

// Byte-mode capacity at level M per version, as test/qr.test.mjs pins it.
const CAPACITY_M = [0, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213];

const PY = (() => {
  for (const bin of ["python3", "python"]) {
    try {
      execFileSync(bin, ["-c", "import qrcode, numpy, PIL"], { stdio: "ignore" });
      return bin;
    } catch {
      // try the next name
    }
  }
  return null;
})();
const pySkip = PY ? false : "python qrcode, numpy and Pillow not all installed (dev-only ground truth)";
const ZBAR = ["/usr/bin/zbarimg", "/usr/local/bin/zbarimg"].find((p) => existsSync(p)) || null;

// ------------------------------------------------- encoder round trip

test("reads back every version and mask the encoder emits", () => {
  for (let v = 1; v <= 10; v++) {
    const text = `v${v}:`.padEnd(CAPACITY_M[v], "k");
    for (let mask = 0; mask <= 7; mask++) {
      const m = qrMatrixForced(text, mask);
      assert.equal((m.length - 17) / 4, v);
      const out = decode(render(m));
      assert.ok(out, `version ${v} mask ${mask} did not decode`);
      assert.equal(out.text, text, `version ${v} mask ${mask}`);
      assert.equal(out.version, v);
      assert.equal(out.mask, mask);
      assert.equal(out.ecc, "M");
    }
  }
});

test("reads a code at larger scales and off center", () => {
  const text = "https://starlingmap.app/#j=Ab3xZ9qLK7mW2fT8pR5vN0cY6sD1jH4gQoUeIaXtM-_";
  const m = qrMatrix(text);
  // Three pixels per module is the floor: the threshold step smooths 3x3.
  for (const scale of [3, 5, 9]) {
    const img = render(m, scale, 6);
    const out = decode(img);
    assert.ok(out, `scale ${scale}`);
    assert.equal(out.text, text);
  }
  // Pasted into a bigger frame, bottom right, like a phone held off center.
  const small = render(m, 4);
  const W = 400;
  const H = 300;
  const frame = new Uint8Array(W * H).fill(230);
  for (let y = 0; y < small.height; y++) {
    frame.set(small.data.subarray(y * small.width, (y + 1) * small.width), (y + H - small.height - 10) * W + W - small.width - 10);
  }
  assert.equal(decode({ width: W, height: H, data: frame })?.text, text);
});

test("accepts RGBA ImageData shaped input, in any two colors", () => {
  const text = "starling:sn:1:0123456789abcdef0123456789abcdef:123456789012345678901234567890";
  const gray = render(qrMatrix(text), 4);
  const rgba = new Uint8ClampedArray(gray.width * gray.height * 4);
  for (let i = 0; i < gray.data.length; i++) {
    const dark = gray.data[i] === 0;
    rgba[i * 4] = dark ? 16 : 250;
    rgba[i * 4 + 1] = dark ? 21 : 245;
    rgba[i * 4 + 2] = dark ? 34 : 230;
    rgba[i * 4 + 3] = 255;
  }
  const out = decode({ width: gray.width, height: gray.height, data: rgba });
  assert.equal(out?.text, text);
  assert.equal(out.version, 5);
});

// ------------------------------------------------------- python fixtures

const fixtures = (() => {
  if (!PY) return null;
  const dir = mkdtempSync(path.join(tmpdir(), "starling-qr-"));
  execFileSync(PY, [GEN, dir], { stdio: ["ignore", "ignore", "pipe"] });
  const manifest = JSON.parse(readFileSync(path.join(dir, "manifest.json"), "utf8"));
  return { dir, manifest };
})();

test.after(() => {
  if (fixtures) rmSync(fixtures.dir, { recursive: true, force: true });
});

// Decode every fixture once; the class tests read the table.
const results = new Map();
if (fixtures) {
  for (const e of fixtures.manifest) {
    const out = decode(readPgm(path.join(fixtures.dir, e.file)));
    results.set(e.file, out);
  }
}

function classOf(e) {
  return e.cls === "damage" ? `damage@${e.frac}` : e.cls;
}

function rate(cls) {
  let n = 0;
  let ok = 0;
  for (const e of fixtures.manifest) {
    if (classOf(e) !== cls) continue;
    n++;
    const out = results.get(e.file);
    if (out && out.text === e.text && out.version === e.version && out.mask === e.mask && out.ecc === e.level) ok++;
  }
  return { n, ok };
}

// The floor each class holds today. Random module flips totalling the whole
// of every block's correction budget land unevenly, so some block always
// gets more than it can fix: that class is expected to lose about half.
const FLOORS = {
  clean: 1,
  rot90: 1,
  rot180: 1,
  rot270: 1,
  rot15: 1,
  persp: 1,
  blur: 1,
  noise: 1,
  "damage@0.25": 1,
  "damage@0.5": 1,
  "damage@1": 0.4,
};

for (const [cls, floor] of Object.entries(FLOORS)) {
  test(`fixture class ${cls} decodes at ${Math.round(floor * 100)}% or better`, { skip: pySkip }, () => {
    const { n, ok } = rate(cls);
    assert.ok(n >= 80, `${cls}: only ${n} fixtures`);
    console.log(`  qrscan ${cls}: ${ok}/${n}`);
    assert.ok(ok >= Math.ceil(floor * n), `${cls}: ${ok}/${n} below ${floor}`);
  });
}

test("the clean fixtures cover versions 1-10, masks 0-7 and all four levels", { skip: pySkip }, () => {
  const seen = new Set();
  for (const e of fixtures.manifest) if (e.cls === "clean") seen.add(`${e.version}/${e.mask}/${e.level}`);
  assert.equal(seen.size, 10 * 8 * 4);
});

test("no fixture anywhere decodes to the wrong text", { skip: pySkip }, () => {
  const wrong = [];
  for (const e of fixtures.manifest) {
    const out = results.get(e.file);
    if (out && out.text !== e.text) wrong.push(`${e.file}: ${JSON.stringify(out.text.slice(0, 30))}`);
  }
  assert.deepEqual(wrong, []);
});

test("zbarimg reads the same text from a sample of the fixtures", { skip: pySkip || (ZBAR ? false : "zbarimg not installed") }, () => {
  let compared = 0;
  let agreed = 0;
  fixtures.manifest.forEach((e, i) => {
    if (i % 9 !== 0) return;
    let zbar = null;
    try {
      zbar = execFileSync(ZBAR, ["-q", "--raw", path.join(fixtures.dir, e.file)], { encoding: "utf8" }).replace(/\n$/, "");
    } catch {
      zbar = null;
    }
    if (e.cls === "clean") assert.equal(zbar, e.text, `zbar on ${e.file}`);
    if (zbar === null) return;
    compared++;
    const ours = results.get(e.file);
    if (ours && ours.text === zbar) agreed++;
    assert.equal(zbar, e.text, `the fixture ${e.file} is not what the manifest says`);
  });
  console.log(`  qrscan vs zbarimg: agreed on ${agreed} of ${compared} the latter read`);
  assert.ok(compared >= 60, `only ${compared} compared`);
  assert.ok(agreed >= compared * 0.95, `${agreed}/${compared}`);
});

// ------------------------------------------------------ negative controls

test("nothing to read gives null, not a guess", () => {
  const W = 160;
  const H = 120;
  assert.equal(decode({ width: W, height: H, data: new Uint8Array(W * H).fill(255) }), null, "white");
  assert.equal(decode({ width: W, height: H, data: new Uint8Array(W * H).fill(0) }), null, "black");
  const rnd = lcg(5);
  const noise = new Uint8Array(W * H);
  for (let i = 0; i < noise.length; i++) noise[i] = rnd() * 256;
  assert.equal(decode({ width: W, height: H, data: noise }), null, "noise");
  const grad = new Uint8Array(W * H);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) grad[y * W + x] = (x * 255) / W;
  assert.equal(decode({ width: W, height: H, data: grad }), null, "gradient");
  const speckle = new Uint8Array(W * H).fill(255);
  for (let i = 0; i < 400; i++) speckle[Math.floor(rnd() * speckle.length)] = 0;
  assert.equal(decode({ width: W, height: H, data: speckle }), null, "speckle");
});

test("malformed input gives null", () => {
  assert.equal(decode(null), null);
  assert.equal(decode({}), null);
  assert.equal(decode({ width: 100, height: 100, data: new Uint8Array(10) }), null, "wrong length");
  assert.equal(decode({ width: 0, height: 0, data: new Uint8Array(0) }), null);
  assert.equal(decode({ width: 10, height: 10, data: new Uint8Array(100) }), null, "too small to hold a code");
  assert.equal(decode({ width: -5, height: 10, data: new Uint8Array(50) }), null);
});

test("a code missing a finder pattern is not read", () => {
  const m = qrMatrix("starling:sn:1:0123456789abcdef0123456789abcdef:123456789012345678901234567890");
  assert.ok(decode(render(m)), "intact code reads");
  const broken = m.map((row) => row.slice());
  for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) broken[y][x] = false;
  assert.equal(decode(render(broken)), null);
});

test("a code with its format information destroyed is not read", () => {
  const m = qrMatrix("S");
  const n = m.length;
  const broken = m.map((row) => row.slice());
  for (let i = 0; i < 8; i++) {
    broken[i < 6 ? i : i + 1][8] = !broken[i < 6 ? i : i + 1][8];
    broken[8][n - i - 1] = !broken[8][n - i - 1];
  }
  assert.equal(decode(render(broken)), null);
});

test("damage past the correction budget gives null or the truth, never another text", () => {
  const text = "starling:sn:1:0123456789abcdef0123456789abcdef:123456789012345678901234567890";
  const m = qrMatrix(text);
  const n = m.length;
  const rnd = lcg(11);
  let nulls = 0;
  for (let trial = 0; trial < 40; trial++) {
    const hit = m.map((row) => row.slice());
    // Version 5 at M corrects 12 codewords per block; 80 flipped modules in
    // the data region is well past both blocks together.
    for (let k = 0; k < 80; k++) {
      const y = 9 + Math.floor(rnd() * (n - 18));
      const x = 9 + Math.floor(rnd() * (n - 18));
      hit[y][x] = !hit[y][x];
    }
    const out = decode(render(hit));
    if (out === null) nulls++;
    else assert.equal(out.text, text, `trial ${trial} read something else`);
  }
  assert.ok(nulls >= 30, `${nulls} of 40 refused`);
});

test("the control that proves the readers see what they claim: a flipped bit changes the answer", () => {
  const text = "starling:sn:1:0123456789abcdef0123456789abcdef:123456789012345678901234567890";
  const m = qrMatrix(text);
  const img = render(m);
  assert.equal(decode(img).text, text);
  const other = qrMatrix(text.slice(0, -1) + "1");
  assert.notEqual(decode(render(other)).text, text);
});

// --------------------------------------------------------- the payload

test("the safety number code carries the id and the digits, and only that shape parses", async () => {
  const me = await generateIdentity();
  const number = await safetyNumber(me.pk, me.epk);
  const text = safetyQrText(me.memberId, number);
  assert.match(text, /^starling:sn:1:[0-9a-f]{32}:\d{30}$/);
  assert.deepEqual(parseSafetyQr(text), { memberId: me.memberId, digits: number.replace(/ /g, "") });
  assert.deepEqual(parseSafetyQr(` ${text}\n`), parseSafetyQr(text), "surrounding whitespace is fine");

  assert.equal(safetyQrText("short", number), null);
  assert.equal(safetyQrText(me.memberId, "12345"), null);
  assert.equal(safetyQrText(me.memberId.toUpperCase(), number), null);
  for (const bad of [
    "",
    null,
    undefined,
    "starling:sn:2:" + text.slice(14),
    text.slice(0, -1),
    text + "0",
    text.replace("starling:", "sparrow:"),
    text.toUpperCase(),
    text.replace(/:(\d{30})$/, ":$1 x"),
    "https://starlingmap.app/#j=abc",
  ]) {
    assert.equal(parseSafetyQr(bad), null, JSON.stringify(bad));
  }
});

test("a scan is checked against the pinned keys, and only an exact match is a match", async () => {
  const ana = await generateIdentity();
  const bo = await generateIdentity();
  const pinned = new Map([
    [ana.memberId, { alg: ana.alg, pk: b64uEncode(ana.pk), epk: b64uEncode(ana.epk), verified: false, name: "Ana" }],
  ]);
  const before = JSON.stringify([...pinned]);
  const anaNumber = await safetyNumber(ana.pk, ana.epk);
  const digits = anaNumber.replace(/ /g, "");

  const match = await checkSafetyQr(safetyQrText(ana.memberId, anaNumber), pinned);
  assert.equal(match.outcome, "match");
  assert.equal(match.memberId, ana.memberId);
  assert.equal(match.number, anaNumber);

  // One digit off: the code says Ana, the keys say otherwise.
  const off = digits.slice(0, 7) + ((Number(digits[7]) + 1) % 10) + digits.slice(8);
  const mismatch = await checkSafetyQr(`starling:sn:1:${ana.memberId}:${off}`, pinned);
  assert.equal(mismatch.outcome, "mismatch");
  assert.equal(mismatch.memberId, ana.memberId);

  // Bo's real number under Ana's id: still a mismatch, the id names the keys.
  const boNumber = await safetyNumber(bo.pk, bo.epk);
  assert.equal((await checkSafetyQr(safetyQrText(ana.memberId, boNumber), pinned)).outcome, "mismatch");

  assert.equal((await checkSafetyQr(safetyQrText(bo.memberId, boNumber), pinned)).outcome, "unknown");

  assert.equal((await checkSafetyQr("hello", pinned)).outcome, "invalid");
  assert.equal((await checkSafetyQr(null, pinned)).outcome, "invalid");
  assert.equal((await checkSafetyQr(safetyQrText(ana.memberId, anaNumber), new Map())).outcome, "unknown");

  // Keys that will not decode have no number to match.
  const junk = new Map([[ana.memberId, { pk: "!!!", epk: "!!!" }]]);
  assert.equal((await checkSafetyQr(safetyQrText(ana.memberId, anaNumber), junk)).outcome, "unknown");

  assert.equal(JSON.stringify([...pinned]), before, "checking is a verdict, never a write");
});

test("the real payload rides a version 5 code through the encoder and back", async () => {
  const me = await generateIdentity();
  const number = await safetyNumber(me.pk, me.epk);
  const text = safetyQrText(me.memberId, number);
  const m = qrMatrix(text);
  assert.equal(m.length, 37, "version 5");
  const out = decode(render(m, 4));
  assert.equal(out?.text, text);
  const pinned = new Map([[me.memberId, { pk: b64uEncode(me.pk), epk: b64uEncode(me.epk) }]]);
  assert.equal((await checkSafetyQr(out.text, pinned)).outcome, "match");
});
