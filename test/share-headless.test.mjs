// "Keep sharing when the app is closed" leaves the page running behind the
// foreground service with no window. A page with no window is hidden, and a
// hidden page's timers get throttled by the renderer: measured on an Android 16
// image, a one second setTimeout had not fired twenty seconds later, while
// script the wrapper pushed in ran immediately.
//
// So nothing that has to happen on time may ride on a page timer alone. These
// pin the two places that mattered: a share stops everything before it waits on
// storage, and a timed share ends off the next position the service pushes
// rather than off its own countdown.
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

const { internals } = await loadApp(harness);
const state = internals.state;
const { openGeneration } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed } = await import("../app/js/crypto.js");

test.after(() => harness.stopTimers());

const calls = [];

async function sharing() {
  calls.length = 0;
  globalThis.StarlingNative = {
    startLocation: () => calls.push("startLocation"),
    stopLocation: () => calls.push("stopLocation"),
    clearStopRecord: () => {},
    keepSharing: () => true,
    setKeepSharing: () => {},
  };
  internals.resetShareResumeGuard();
  state.demo = false;
  state.locked = false;
  state.stopRecord = null;
  state.geoDenied = false;
  state.geoFailed = false;
  state.identity = state.identity || (await generateIdentity());
  if (!state.gen) {
    state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
    state.gen.at = Date.now();
    state.genRoster = new Set();
    state.pinned = new Map();
  }
  internals.setupNet();
  if (!state.sharing) await internals.setSharing(true);
  assert.equal(state.sharing, true, "sharing is on to begin with");
  assert.ok(typeof globalThis.__starlingFix === "function", "the wrapper fix sink is armed");
}

test("stopping a share tears everything down before it waits on storage", async () => {
  await sharing();
  calls.length = 0;

  // Deliberately not awaited: everything that stops something has to have
  // happened by the time this call returns, because after the first await the
  // renderer decides when the rest of it runs.
  const done = internals.setSharing(false);

  assert.equal(state.sharing, false, "the share is off in the same turn");
  assert.deepEqual(calls, ["stopLocation"], "and the location watch is already stopped");
  assert.equal(internals.shareStatus().deadline, null, "with no countdown left running");

  await done;
  await settle();
});

test("a timed share ends off the next position, not off its own countdown", async () => {
  await sharing();
  internals.setShareWindow(60_000);
  const deadline = internals.shareStatus().deadline;
  assert.ok(deadline, "there is a deadline to miss");

  // A throttled timer, from the page's side: the deadline is in the past and
  // setTimeout has not had a turn. Node's timers are not throttled, so the
  // clock moves instead of the wait.
  const realNow = Date.now;
  Date.now = () => realNow() + 61_000;
  try {
    calls.length = 0;
    globalThis.__starlingFix(JSON.stringify({ lat: 45.06, lon: 13.23, ts: realNow(), acc: 8 }));
    await settle(50);
  } finally {
    Date.now = realNow;
  }

  assert.equal(state.sharing, false, "the share is over");
  assert.deepEqual(calls, ["stopLocation"], "and the wrapper was told to stop watching");
  assert.equal(internals.shareStatus().deadline, null, "with the deadline cleared");
});

test("a fix inside the window leaves a timed share alone", async () => {
  await sharing();
  internals.setShareWindow(600_000);
  globalThis.__starlingFix(JSON.stringify({ lat: 45.06, lon: 13.23, ts: Date.now(), acc: 8 }));
  await settle(50);
  assert.equal(state.sharing, true, "ten minutes left is not a deadline passed");
  assert.ok(internals.shareStatus().deadline > Date.now(), "and the deadline stands");
  await internals.setSharing(false);
  await settle();
  delete globalThis.StarlingNative;
});

test("a phone that is not moving still posts off the fixes the service pushes", async () => {
  for (const steady of [false, true]) {
    state.settings.steady = steady;
    await internals.setSharing(false);
    await sharing();
    const posts = [];
    const realFetch = globalThis.fetch;
    const realNow = Date.now;
    globalThis.fetch = async (url, opts) => {
      if (opts?.method === "POST") posts.push(String(url));
      return new Response("{}", { status: 200 });
    };
    try {
      const t0 = realNow();
      const at = (ms) => (Date.now = () => t0 + ms);
      const fix = { lat: 40.785, lon: -73.968, acc: 5, ts: t0 };
      at(0);
      globalThis.__starlingFix(JSON.stringify(fix));
      await settle();
      const first = posts.length;
      assert.ok(first >= 1, `steady=${steady}: the first fix posts`);
      at(5000);
      globalThis.__starlingFix(JSON.stringify({ ...fix, ts: t0 + 5000 }));
      await settle();
      assert.equal(posts.length, first, `steady=${steady}: same spot inside the interval posts nothing`);
      at(16000);
      globalThis.__starlingFix(JSON.stringify({ ...fix, ts: t0 + 16000 }));
      await settle();
      assert.equal(posts.length, first + 1, `steady=${steady}: same spot after the interval posts again`);
    } finally {
      globalThis.fetch = realFetch;
      Date.now = realNow;
      state.settings.steady = false;
    }
  }
});

test("auto-lock waits out a share kept past the app closing, and only that", async () => {
  await sharing();
  const own = Object.getOwnPropertyDescriptor(document, "visibilityState");
  Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
  const prevLock = state.lock;
  state.lock = { enabled: true, autolockMs: 60000 };
  try {
    internals.armAutoLock();
    assert.equal(internals.lockArmed(), false, "switch on: no lock timer while sharing");
    globalThis.StarlingNative.keepSharing = () => false;
    internals.armAutoLock();
    assert.equal(internals.lockArmed(), true, "switch off: the lock timer runs as before");
    globalThis.StarlingNative.keepSharing = () => true;
    internals.armAutoLock();
    await internals.setSharing(false);
    assert.equal(internals.lockArmed(), true, "and it arms the moment the kept share ends");
  } finally {
    state.lock = { enabled: false };
    internals.armAutoLock();
    state.lock = prevLock;
    delete document.visibilityState;
    if (own) Object.defineProperty(document, "visibilityState", own);
  }
});
