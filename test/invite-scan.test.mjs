// Only an invite read by the real decoder reaches the join handler; anything else keeps the camera looking.
import test from "node:test";
import assert from "node:assert/strict";

import { installDom, loadApp } from "./dom-harness.mjs";

const harness = installDom();
globalThis.indexedDB ??= {
  open() {
    throw new Error("no indexeddb in the harness");
  },
  deleteDatabase() {
    const req = {};
    setTimeout(() => req.onsuccess?.(), 0);
    return req;
  },
};
const { internals } = await loadApp(harness);
const { qrMatrix } = await import("../app/js/qr.js");
const { decode } = await import("../app/js/qrscan.js");
const { inviteFragment, generateIdentity } = await import("../app/js/crypto.js");
const { safetyQrText } = await import("../app/js/roster.js");
const { safetyNumber } = await import("../app/js/wire.js");

test.after(() => harness.stopTimers());

function render(m, scale = 4, quiet = 4) {
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

const scanned = (text) => decode(render(qrMatrix(text)))?.text;

function inviteLink(relay = "") {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const commit = crypto.getRandomValues(new Uint8Array(16));
  return { secret, link: `https://starlingmap.app/${inviteFragment(secret, commit, relay)}` };
}

test("an invite code read by the camera reaches the join handler", () => {
  const { secret, link } = inviteLink();
  const text = scanned(link);
  assert.equal(text, link, "the decoder reads the link back");
  assert.equal(internals.inviteScanProblem(text), null);
  const joined = [];
  assert.equal(internals.joinFromScan(text, (invite) => joined.push(invite)), true);
  assert.equal(joined.length, 1);
  assert.deepEqual([...joined[0].secret], [...secret]);
  assert.equal(joined[0].relay, "");
});

test("an invite for a circle on its own relay keeps the relay", () => {
  const { link } = inviteLink("https://relay.example.org");
  const joined = [];
  internals.joinFromScan(scanned(link), (invite) => joined.push(invite));
  assert.equal(joined[0]?.relay, "https://relay.example.org");
});

test("a safety number code is named for what it is and joins nothing", async () => {
  const me = await generateIdentity();
  const text = scanned(safetyQrText(me.memberId, await safetyNumber(me.pk, me.epk)));
  assert.equal(internals.inviteScanProblem(text), "That is a safety number code, not an invite.");
  const joined = [];
  assert.equal(internals.joinFromScan(text, (invite) => joined.push(invite)), false);
  assert.deepEqual(joined, []);
});

test("anything else is not an invite, and joins nothing", () => {
  for (const text of [scanned("https://example.org/hello"), "https://starlingmap.app/#j=abc", "", "j=nope"]) {
    assert.equal(internals.inviteScanProblem(text), "That is not a Starling invite code.", JSON.stringify(text));
    const joined = [];
    assert.equal(internals.joinFromScan(text, (invite) => joined.push(invite)), false);
    assert.deepEqual(joined, []);
  }
});

test("the paste field reads a link, a bare fragment and j= alike", () => {
  const { link } = inviteLink();
  const frag = link.slice(link.indexOf("#"));
  for (const text of [link, ` ${link}\n`, frag, frag.slice(1)]) {
    assert.ok(internals.inviteFromText(text), JSON.stringify(text));
  }
});
