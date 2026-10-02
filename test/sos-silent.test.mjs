// An SOS whose phone goes quiet is still an SOS to the people watching.
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
const state = internals.state;
const { openGeneration } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed, sealMessage, buildPost } = await import("../app/js/crypto.js");
const { b64uEncode } = await import("../app/js/wire.js");
const { statusOf, displayStatus, sortMembers, STALE_MS } = await import("../app/js/net.js");

test.after(() => {
  delete globalThis.StarlingNative;
  harness.stopTimers();
});

async function inCircle() {
  state.demo = false;
  state.locked = false;
  state.identity = await generateIdentity();
  state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
  state.gen.at = Date.now();
  state.genRoster = new Set();
  state.pinned = new Map();
  internals.resetMemberAlerts();
  internals.setupNet();
}

async function feed(who, fields, ts) {
  const gen = state.gen;
  const e = epochAt(ts);
  const key = await gen.ratchet.keyFor(e, who.memberId, ts);
  const sealed = await sealMessage(key, gen.channelId, who.memberId, e, ts, { v: 2, ts, ...fields });
  const post = await buildPost(who, gen.channelId, e, sealed, ts);
  await internals.roster().ingest(
    [
      {
        m: who.memberId,
        alg: who.alg,
        pk: b64uEncode(who.pk),
        epk: b64uEncode(who.epk),
        points: [{ e: post.e, ts: post.ts, srv: post.ts, n: post.n, c: post.c, sig: post.sig }],
      },
    ],
    ts,
  );
}

function withClock(fn) {
  const realNow = Date.now;
  const at = (ms) => (Date.now = () => ms);
  return Promise.resolve(fn(at)).finally(() => {
    Date.now = realNow;
  });
}

const QUIET = STALE_MS + 1000;

test("statusOf still calls a silent SOS stale", () => {
  const now = 1_800_000_000_000;
  const rec = { id: "a", type: "sos", ts: now - QUIET };
  assert.equal(statusOf(rec, now), "stale", "the help viewer reads this as Signal lost, and must keep doing so");
  assert.equal(statusOf({ ...rec, ts: now - 1000 }, now), "sos");
});

test("displayStatus keeps a silent SOS first in sortMembers", () => {
  const now = 1_800_000_000_000;
  const live = { id: "live", type: "loc", ts: now - 1000 };
  const quiet = { id: "quiet", type: "sos", ts: now - 10 * 60 * 1000 };
  const gone = { id: "gone", type: "bye", ts: now - 500 };
  assert.equal(displayStatus(quiet, now), "sos");
  assert.deepEqual(sortMembers([live, gone, quiet], now).map((r) => r.id), ["quiet", "live", "gone"]);
  assert.equal(displayStatus({ ...quiet, type: "bye" }, now), "stopped", "a bye ends it");
  assert.equal(displayStatus({ ...quiet, type: "loc" }, now), "stale", "so does any later message");
});

test("an SOS that goes quiet fires one urgent notification", async () => {
  await inCircle();
  const calls = [];
  globalThis.StarlingNative = {
    windowShown: () => false,
    notify: (...a) => calls.push(a),
    cancelNotify: () => {},
  };
  const who = await generateIdentity();
  const t0 = Date.now();
  await feed(who, { t: "sos", name: "Juno", lat: 1, lon: 2 }, t0);
  await withClock((at) => {
    at(t0 + 1000);
    internals.checkAlerts();
    assert.deepEqual(calls.map((c) => c[0]), ["SOS from Juno"]);

    at(t0 + QUIET);
    internals.checkAlerts();
    at(t0 + QUIET + 60_000);
    internals.checkAlerts();
    const quiet = calls.filter((c) => c[0] === "Juno's SOS went quiet");
    assert.equal(quiet.length, 1, "said once per SOS, not once per poll");
    assert.equal(quiet[0][2], `sos-${who.memberId}`, "it replaces the SOS notification rather than stacking");
    assert.equal(quiet[0][3], true, "and rings like one");
    assert.equal(quiet[0][1], "Their last position is on the map.");
  });
});

test("an incoming SOS card stays until check-in", async () => {
  await inCircle();
  globalThis.StarlingNative = { windowShown: () => true };
  const who = await generateIdentity();
  const id = `sos:${who.memberId}`;
  const card = () => internals.alertItems().find((i) => i.id === id);
  const t0 = Date.now();
  await feed(who, { t: "sos", name: "Juno", lat: 1, lon: 2 }, t0);
  await withClock(async (at) => {
    at(t0 + 1000);
    internals.checkAlerts();
    assert.ok(card(), "an incoming SOS puts a card on the sheet");
    assert.equal(card().kind, "sos");
    assert.equal(card().title, "SOS from Juno");
    assert.match(card().text, /stays here until they check in/);
    assert.deepEqual(card().actions.map((a) => a.label), ["Show on map", "Got it"]);

    at(t0 + QUIET);
    internals.checkAlerts();
    assert.ok(card(), "a phone going quiet does not take the card away");
    assert.match(card().text, /Juno's phone stopped sending .* ago\. The last position it sent is on the map\./);

    card().actions[1].onClick();
    assert.equal(card(), undefined, "Got it hides it");
    internals.checkAlerts();
    assert.equal(card(), undefined, "and it stays hidden for this SOS");

    await feed(who, { t: "loc", name: "Juno", lat: 1, lon: 2 }, t0 + QUIET + 1000);
    at(t0 + QUIET + 2000);
    internals.checkAlerts();
    await feed(who, { t: "sos", name: "Juno", lat: 1, lon: 2 }, t0 + QUIET + 3000);
    at(t0 + QUIET + 4000);
    internals.checkAlerts();
    assert.ok(card(), "the next SOS brings it back");

    await feed(who, { t: "checkin", name: "Juno" }, t0 + QUIET + 5000);
    at(t0 + QUIET + 6000);
    internals.checkAlerts();
    assert.equal(card(), undefined, "a check-in clears it");
  });
});
