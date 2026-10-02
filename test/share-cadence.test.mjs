// Per-circle cadence, held against the real main.js: the wrapper hears the
// active circle's number before every start and on every change, the page's
// own timer follows it, an SOS ignores it, and the sealed post carries both
// the cadence and the circle's precision rather than the device default.
import test from "node:test";
import assert from "node:assert/strict";

import { installDom, loadApp, settle } from "./dom-harness.mjs";

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

const { internals, api } = await loadApp(harness);
const state = internals.state;
const { openGeneration } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed, openMessage } = await import("../app/js/crypto.js");
const { b64uDecode } = await import("../app/js/wire.js");
const { dbGet } = await import("../app/js/store.js");
const { coarsePos } = await import("../app/js/fmt.js");

test.after(() => harness.stopTimers());

const calls = [];
const periods = [];

// Every interval the app arms, with its period, so the share timer's cadence
// can be read rather than waited for.
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (fn, ms, ...rest) => {
  periods.push(ms);
  return realSetInterval(fn, ms, ...rest);
};

async function sharing(share = { precision: null, cadence: null }) {
  if (state.sharing) await internals.setSharing(false);
  calls.length = 0;
  periods.length = 0;
  globalThis.StarlingNative = {
    startLocation: () => calls.push("startLocation"),
    stopLocation: () => calls.push("stopLocation"),
    setShareCadence: (s) => calls.push(`setShareCadence:${s}`),
    clearStopRecord: () => {},
    keepSharing: () => false,
    setKeepSharing: () => {},
    windowShown: () => true,
    pulse: () => {},
  };
  internals.resetShareResumeGuard();
  state.demo = false;
  state.locked = false;
  state.stopRecord = null;
  state.sosActive = false;
  state.circleShare = share;
  state.identity = state.identity || (await generateIdentity());
  if (!state.gen) {
    state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
    state.gen.at = Date.now();
    state.genRoster = new Set();
    state.pinned = new Map();
  }
  internals.setupNet();
  await internals.setSharing(true);
  assert.equal(state.sharing, true);
}

// Decrypt a captured location POST the way a circle member would.
async function openOwnPost(body) {
  const p = JSON.parse(body);
  const key = await state.gen.ratchet.keyFor(p.e, state.identity.memberId, p.ts);
  return openMessage(key, state.gen.channelId, state.identity.memberId, p.e, p.ts, b64uDecode(p.n), b64uDecode(p.c));
}

// The circle's posts only: an SOS also starts a beacon on a channel of its
// own, and those posts are sealed to a key this helper does not hold.
function capturePosts() {
  const posts = [];
  harness.onFetch(async (url, init) => {
    if (url.includes(`/f/${state.gen.channelId}/loc`)) posts.push(init.body);
    return undefined;
  });
  return posts;
}

test("the wrapper hears the circle's cadence before the share starts, and the timer runs on it", async () => {
  await sharing({ precision: null, cadence: 300 });
  assert.deepEqual(calls.slice(0, 2), ["setShareCadence:300", "startLocation"], "the number lands before the start");
  assert.ok(periods.includes(300_000), `the share timer runs every five minutes, got ${periods.join(",")}`);

  await sharing();
  assert.deepEqual(calls.slice(0, 2), ["setShareCadence:15", "startLocation"], "a circle with none is today's 15 seconds");
  assert.ok(periods.includes(15_000));
  assert.ok(!periods.includes(300_000));
});

test("a cadence below the floor goes to the wrapper as 15", async () => {
  await sharing({ precision: null, cadence: 5 });
  assert.equal(calls[0], "setShareCadence:15");
  assert.equal(internals.shareCadence(), 15);
  assert.ok(periods.includes(15_000));
});

test("changing the cadence under a running share re-arms the timer, the wrapper and the disk", async () => {
  await sharing({ precision: null, cadence: 15 });
  calls.length = 0;
  periods.length = 0;
  await api.setSetting("cadence", 60);
  assert.deepEqual(calls, ["setShareCadence:60"]);
  assert.deepEqual(periods, [60_000], "the old timer went and a one minute one took its place");
  assert.deepEqual(state.circleShare, { precision: "precise", cadence: 60 }, "both values resolved and kept together");
  assert.deepEqual(await dbGet("circleShare"), { precision: "precise", cadence: 60 });
  assert.equal(internals.shareCadence(), 60);
});

test("an SOS posts every 15 seconds whatever the circle asked for, and a check-in hands the cadence back", async () => {
  await sharing({ precision: null, cadence: 300 });
  state.me = { lat: 40.785, lon: -73.968, acc: 5, ts: Date.now() };
  const posts = capturePosts();
  calls.length = 0;
  periods.length = 0;
  try {
    await internals.fireSos();
    await settle();
    assert.ok(calls.includes("setShareCadence:15"), `the wrapper was moved to the floor, got ${calls.join(",")}`);
    assert.ok(periods.includes(15_000), "and so was the timer");
    const sos = await openOwnPost(posts.at(-1));
    assert.equal(sos.t, "sos");
    assert.equal(sos.cadence, 15, "receivers are told to expect it every 15 seconds");

    calls.length = 0;
    periods.length = 0;
    await internals.doCheckin();
    await settle();
    assert.ok(calls.includes("setShareCadence:300"), "back to the circle's cadence");
    assert.ok(periods.includes(300_000));
    const checkin = await openOwnPost(posts.at(-1));
    assert.equal(checkin.t, "checkin");
    assert.equal(checkin.cadence, 300);
  } finally {
    harness.onFetch(null);
    state.sosActive = false;
  }
});

test("the post carries the circle's own precision and cadence, not the device default", async () => {
  await sharing({ precision: "coarse", cadence: 60 });
  state.settings = { ...state.settings, precision: "precise" };
  const fix = { lat: 40.7851, lon: -73.9683, acc: 5 };
  state.me = { ...fix, ts: Date.now() };
  const posts = capturePosts();
  try {
    await internals.sendLoc(true);
    await settle();
    const coarse = await openOwnPost(posts.at(-1));
    assert.equal(coarse.mode, "coarse");
    assert.equal(coarse.cadence, 60);
    assert.deepEqual({ lat: coarse.lat, lon: coarse.lon }, coarsePos(fix.lat, fix.lon), "rounded on this device");
    assert.equal(coarse.acc, undefined);

    // The same device, a circle with no choice of its own: the default speaks.
    state.circleShare = { precision: null, cadence: null };
    await internals.sendLoc(true);
    await settle();
    const precise = await openOwnPost(posts.at(-1));
    assert.equal(precise.mode, "precise");
    assert.equal(precise.cadence, 15);
    assert.equal(precise.lat, fix.lat);
    assert.equal(precise.acc, 5);
  } finally {
    harness.onFetch(null);
  }
});

test("a tick from the service resends only once the cadence has passed", async () => {
  await sharing({ precision: null, cadence: 300 });
  const posts = capturePosts();
  const realNow = Date.now;
  try {
    const t0 = realNow();
    const at = (ms) => (Date.now = () => t0 + ms);
    at(0);
    state.me = { lat: 40.785, lon: -73.968, acc: 5, ts: t0 };
    await internals.sendLoc(true);
    await settle();
    const first = posts.length;
    assert.ok(first >= 1);
    at(60_000);
    internals.onShareSignal({ tick: true });
    await settle();
    assert.equal(posts.length, first, "a minute with no fix is not five, so nothing goes");
    at(300_000);
    internals.onShareSignal({ tick: true });
    await settle();
    assert.equal(posts.length, first + 1, "once the cadence has passed the tick posts");
  } finally {
    Date.now = realNow;
    harness.onFetch(null);
  }
});

test.after(async () => {
  if (state.sharing) await internals.setSharing(false);
  globalThis.setInterval = realSetInterval;
  delete globalThis.StarlingNative;
});
