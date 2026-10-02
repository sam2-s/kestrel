// Sharing survives the process now, which is what two people reported from
// four phones: the app was closed while sharing, and reopening showed sharing
// off with no way back except turning it on again.
//
// Sharing itself is still RAM (state.sharing, the poll timer, the geolocation
// watch), so a swipe still ends the live share; what is new is the record that
// says one was running, and the resume at the end of entering a circle. These
// checks pin the four decisions in that resume: it comes back after a swipe or
// a process death, it does NOT come back after a person pressed Stop on the
// notification, it does not outlive a timed share's window, and it never runs
// while the app is locked, because a locked device holds no keys.
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
const { dbGet, dbSet, dbDel } = await import("../app/js/store.js");

test.after(() => harness.stopTimers());

const SHARE_ARMED = "shareArmed";

// The resume needs a circle with a sender, and a location source. The wrapper
// bridge is the same stand-in share-stop-trace.test.mjs uses: startWatch arms
// a native fix sink through it rather than asking a browser for geolocation.
const { openGeneration } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed } = await import("../app/js/crypto.js");

function nativeStub() {
  globalThis.StarlingNative = {
    startLocation() {},
    stopLocation() {},
    clearStopRecord() {},
  };
}

async function armedWorld({ armed, stopRecord = null, locked = false }) {
  internals.resetShareResumeGuard();
  nativeStub();
  state.demo = false;
  state.locked = locked;
  state.sharing = false;
  state.stopRecord = stopRecord;
  state.geoDenied = false;
  state.geoFailed = false;
  state.identity = state.identity || (await generateIdentity());
  if (!state.gen) {
    state.gen = await openGeneration({
      seed: new Uint8Array(newSeed()),
      g: 0,
      e0: epochAt(Date.now()),
    });
    state.gen.at = Date.now();
    state.genRoster = new Set();
    state.pinned = new Map();
  }
  // enterCircle builds the sender the resume checks for; the harness has no
  // relay, so arming the net directly is both enough and honest about what is
  // under test here.
  internals.setupNet();
  if (armed) {
    await dbSet(SHARE_ARMED, armed);
  } else {
    await dbDel(SHARE_ARMED);
  }
}

test("a share that died with the process comes back on the next open", async () => {
  await armedWorld({ armed: { at: Date.now() - 60_000, windowMs: 0, deadline: 0 } });
  const resumed = await internals.resumeShareIfArmed();
  await settle();
  assert.equal(resumed, true, "the resume ran");
  assert.equal(state.sharing, true, "and sharing is on again");
  assert.ok(await dbGet(SHARE_ARMED), "the record stays, because the share is running again");
  await internals.setSharing(false);
});

test("a swipe is not a decision, so it resumes too", async () => {
  await armedWorld({
    armed: { at: Date.now() - 60_000, windowMs: 0, deadline: 0 },
    stopRecord: { route: "swipe", at: Date.now() - 30_000 },
  });
  assert.equal(await internals.resumeShareIfArmed(), true);
  assert.equal(state.sharing, true);
  await internals.setSharing(false);
});

test("Stop on the notification IS a decision, and is never undone by a reopen", async () => {
  await armedWorld({
    armed: { at: Date.now() - 60_000, windowMs: 0, deadline: 0 },
    stopRecord: { route: "notif", at: Date.now() - 30_000 },
  });
  assert.equal(await internals.resumeShareIfArmed(), false);
  assert.equal(state.sharing, false, "sharing stays off");
  assert.equal(await dbGet(SHARE_ARMED), undefined, "and the record is cleared, so it cannot fire later");
});

test("a timed share whose window ran out while the app was closed stays ended", async () => {
  await armedWorld({
    armed: { at: Date.now() - 3_600_000, windowMs: 60_000, deadline: Date.now() - 60_000 },
  });
  assert.equal(await internals.resumeShareIfArmed(), false);
  assert.equal(state.sharing, false);
  assert.equal(await dbGet(SHARE_ARMED), undefined);
});

test("a timed share with time left comes back with the remainder, not the whole window", async () => {
  const deadline = Date.now() + 120_000;
  await armedWorld({ armed: { at: Date.now() - 60_000, windowMs: 180_000, deadline } });
  assert.equal(await internals.resumeShareIfArmed(), true);
  assert.equal(state.sharing, true);
  const left = internals.shareStatus().deadline - Date.now();
  assert.ok(left > 60_000 && left <= 121_000, `about two minutes left, got ${left}ms`);
  await internals.setSharing(false);
});

test("a locked device does not resume a share, because it holds no keys", async () => {
  await armedWorld({ armed: { at: Date.now() - 60_000, windowMs: 0, deadline: 0 }, locked: true });
  assert.equal(await internals.resumeShareIfArmed(), false);
  assert.equal(state.sharing, false);
  assert.ok(await dbGet(SHARE_ARMED), "the record survives the lock, so unlocking can still resume");
});

// Nothing clears the native stop record except a person dismissing the card,
// so a Stop pressed last week is still sitting there during every share after
// it. Without the timestamp it would veto each of their resumes, which is the
// reported bug coming back through the fix for it.
test("a Stop from before this share started does not veto the resume", async () => {
  const startedAt = Date.now() - 60_000;
  await armedWorld({
    armed: { at: startedAt, windowMs: 0, deadline: 0 },
    stopRecord: { route: "notif", at: startedAt - 86_400_000 },
  });
  assert.equal(await internals.resumeShareIfArmed(), true, "a day-old Stop is about a share that is over");
  assert.equal(state.sharing, true);
  await internals.setSharing(false);
});

test("a Stop with no timestamp is treated as a decision, because refusing is the safe way to be wrong", async () => {
  await armedWorld({
    armed: { at: Date.now() - 60_000, windowMs: 0, deadline: 0 },
    stopRecord: { route: "notif" },
  });
  assert.equal(await internals.resumeShareIfArmed(), false);
  assert.equal(state.sharing, false);
});

// The card says the app being closed stops sharing every time. After a resume
// that is flatly untrue, and it was sitting there under a toast saying the
// opposite.
test("the swipe card stops claiming sharing ended once the resume put it back", async () => {
  await armedWorld({
    armed: { at: Date.now() - 60_000, windowMs: 0, deadline: 0 },
    stopRecord: { route: "swipe", at: Date.now() - 30_000 },
  });
  assert.equal(await internals.resumeShareIfArmed(), true);

  const card = internals.alertItems().find((i) => i.id === "stop-record");
  assert.ok(card, "the warning still stands: something closed the app mid-share");
  assert.match(card.text, /put it back on/, "and it says what actually happened");
  assert.doesNotMatch(card.text, /stops it every time/);

  await internals.setSharing(false);
  const after = internals.alertItems().find((i) => i.id === "stop-record");
  assert.match(after.text, /stops it every time/, "with sharing off again the general rule is the true thing to say");
});

test("no record means no resume", async () => {
  await armedWorld({ armed: null });
  assert.equal(await internals.resumeShareIfArmed(), false);
  assert.equal(state.sharing, false);
});

test("the resume is tried once per process, not on every circle entry", async () => {
  await armedWorld({ armed: { at: Date.now() - 60_000, windowMs: 0, deadline: 0 } });
  assert.equal(await internals.resumeShareIfArmed(), true);
  await internals.setSharing(false);
  // Still armed as far as a second call knows, but the guard has been spent.
  await dbSet(SHARE_ARMED, { at: Date.now(), windowMs: 0, deadline: 0 });
  assert.equal(await internals.resumeShareIfArmed(), false, "the second call is a no-op");
  assert.equal(state.sharing, false);
  await dbDel(SHARE_ARMED);
});

test("turning sharing on records it, and stopping by hand clears the record", async () => {
  await armedWorld({ armed: null });

  await internals.setSharing(true);
  await settle();
  assert.equal(state.sharing, true);
  const armed = await dbGet(SHARE_ARMED);
  assert.ok(armed, "a running share is written down");
  assert.ok(armed.at > 0, "with the time it started");

  await internals.setSharing(false);
  await settle();
  assert.equal(await dbGet(SHARE_ARMED), undefined, "and a deliberate stop takes it away");
});
