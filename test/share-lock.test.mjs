// The app lock during a share (munzzyy/starling#6). A locked Starling holds no
// keys, so a share cannot outlive the lock, but it used to end in silence: the
// bye was cancelled before it went, nothing told the sharer, and the circle
// only saw the dot go grey minutes later.
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
const { dbGet, dbSet } = await import("../app/js/store.js");
const { openGeneration } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed } = await import("../app/js/crypto.js");

test.after(() => harness.stopTimers());

const calls = [];
let keep = false;

async function sharingWithLock(autolockMs) {
  calls.length = 0;
  keep = false;
  globalThis.StarlingNative = {
    startLocation: () => calls.push("startLocation"),
    stopLocation: () => calls.push("stopLocation"),
    clearStopRecord: () => calls.push("clearStopRecord"),
    keepSharing: () => keep,
    setKeepSharing: (on) => {
      keep = on;
      calls.push(`setKeepSharing:${on}`);
    },
    windowShown: () => document.visibilityState === "visible",
    pulse: () => {},
    shareEndedByLock: () => calls.push("shareEndedByLock"),
  };
  internals.resetShareResumeGuard();
  document.visibilityState = "visible";
  state.demo = false;
  state.locked = false;
  state.lock = null;
  state.stopRecord = null;
  state.sosActive = false;
  state.settings = { ...state.settings, lockShareNoted: false };
  state.identity = state.identity || (await generateIdentity());
  if (!state.gen) {
    state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
    state.gen.at = Date.now();
    state.genRoster = new Set();
    state.pinned = new Map();
  }
  if (state.sharing) await internals.setSharing(false);
  internals.setupNet();
  await internals.setSharing(true);
  assert.equal(state.sharing, true);
  state.lock = { enabled: true, autolockMs };
}

function holdPosts() {
  const posts = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (url, opts) => {
    if (opts?.method === "POST" && String(url).endsWith("/loc")) {
      return new Promise((resolve) => posts.push(() => resolve(new Response("{}", { status: 200 }))));
    }
    return realFetch(url, opts);
  };
  return { posts, restore: () => (globalThis.fetch = realFetch) };
}

const lockCard = () => internals.alertItems().find((i) => i.id === "lock-share");

test("a share with the lock on says up front that the lock would end it, and one tap keeps it going", async () => {
  await sharingWithLock(60_000);
  const card = lockCard();
  assert.ok(card, "the card is there while sharing with the lock on and keep-sharing off");
  card.actions.find((a) => a.testid === "alert-lock-share-keep").onClick();
  assert.equal(keep, true, "the tap turns keep-sharing on");
  assert.equal(state.settings.lockShareNoted, true);
  assert.equal(lockCard(), undefined, "and the card is gone");

  document.visibilityState = "hidden";
  internals.armAutoLock();
  assert.equal(internals.lockArmed(), false, "with it on, leaving the app starts no lock countdown during the share");
  document.visibilityState = "visible";
  internals.armAutoLock();
  await internals.setSharing(false);
});

test("Not now is remembered, and the lock keeps counting as before", async () => {
  await sharingWithLock(60_000);
  lockCard().actions.find((a) => a.testid === "alert-lock-share-later").onClick();
  assert.equal(state.settings.lockShareNoted, true);
  assert.equal(lockCard(), undefined);
  assert.equal(keep, false, "nothing changed behind the person's back");
  document.visibilityState = "hidden";
  internals.armAutoLock();
  assert.equal(internals.lockArmed(), true);
  document.visibilityState = "visible";
  internals.armAutoLock();
  assert.equal(internals.lockArmed(), false);
  await internals.setSharing(false);
});

test("no card without the lock, or once keep-sharing is already on", async () => {
  await sharingWithLock(60_000);
  state.lock = { enabled: false };
  assert.equal(lockCard(), undefined, "lock off");
  state.lock = { enabled: true, autolockMs: 60_000 };
  keep = true;
  assert.equal(lockCard(), undefined, "keep-sharing on");
  keep = false;
  await internals.setSharing(false);
});

test("SOS stays on the line under your name when location goes off", async () => {
  await internals.enterCircle();
  await sharingWithLock(60_000);
  assert.equal(state.screen, "map", "the line is on the map screen");
  state.lock = null;
  state.sosActive = true;
  state.me = { lat: 40.78, lon: -73.97, ts: Date.now(), acc: 5 };
  internals.onShareSignal({ paused: "location-off" });
  assert.match(harness.node("#you-sub").textContent, /SOS armed · Location is off/);
  state.sosActive = false;
  internals.onShareSignal({ paused: "location-off" });
  assert.match(harness.node("#you-sub").textContent, /Location is off on this phone/);
  internals.onShareSignal({ paused: "" });
  await internals.setSharing(false);
});

test("a share ended by the lock comes back with the lock named, and only for its own record", async () => {
  await sharingWithLock(60_000);
  state.lock = null;
  await internals.setSharing(false);
  const at = Date.now() - 60_000;
  await dbSet("shareArmed", { at, windowMs: 0, deadline: 0 });
  internals.resetShareResumeGuard();
  state.stopRecord = { route: "lock", at: at + 30_000 };
  const toasts = harness.node("#toasts");
  toasts.children.length = 0;
  assert.equal(await internals.resumeShareIfArmed(), true);
  assert.match(toasts.children.at(-1)?.textContent ?? "", /The app lock had ended your share/);
  await internals.setSharing(false);

  // A lock record older than the share: not this share's story.
  await dbSet("shareArmed", { at: Date.now(), windowMs: 0, deadline: 0 });
  internals.resetShareResumeGuard();
  state.stopRecord = { route: "lock", at: Date.now() - 86_400_000 };
  toasts.children.length = 0;
  assert.equal(await internals.resumeShareIfArmed(), true);
  assert.match(toasts.children.at(-1)?.textContent ?? "", /Sharing was on when the app closed/);
  await internals.setSharing(false);
  state.stopRecord = null;
});

// The last two lock the app.
test("the lock ends a share out loud: the bye goes first, then the lock, and the share stays armed", async () => {
  await sharingWithLock(0);
  const held = holdPosts();
  try {
    document.visibilityState = "hidden";
    internals.armAutoLock();
    await settle(200);
    assert.ok(calls.includes("shareEndedByLock"), "the wrapper records it and gives the notice");
    assert.equal(state.stopRecord?.route, "lock");
    assert.equal(state.sharing, false);
    assert.equal(held.posts.length, 1, "the bye is on its way");
    assert.equal(state.locked, false, "and the lock waits for it");
    held.posts[0]();
    await settle(50);
    assert.equal(state.locked, true, "then locks");
    assert.ok(await dbGet("shareArmed"), "still armed, so unlocking brings the share back");
  } finally {
    held.restore();
    document.visibilityState = "visible";
  }
});

test("a bye that never answers holds the lock off for seconds, not for good", async () => {
  await sharingWithLock(0);
  const held = holdPosts();
  try {
    document.visibilityState = "hidden";
    internals.armAutoLock();
    await settle(200);
    assert.equal(held.posts.length, 1);
    assert.equal(state.locked, false);
    await settle(5200);
    assert.equal(state.locked, true, "locked anyway once the wait runs out");
  } finally {
    held.restore();
    document.visibilityState = "visible";
  }
});
