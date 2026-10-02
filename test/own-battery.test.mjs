// Your own low battery offers the slow cadence instead of choosing it for you.
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

const battery = { level: 1 };
navigator.getBattery = async () => battery;

const { internals } = await loadApp(harness);
const state = internals.state;
const { openGeneration } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed } = await import("../app/js/crypto.js");

test.after(async () => {
  if (state.sharing) await internals.setSharing(false);
  delete globalThis.StarlingNative;
  harness.stopTimers();
});

async function sharing() {
  if (state.sharing) await internals.setSharing(false);
  globalThis.StarlingNative = {
    startLocation: () => {},
    stopLocation: () => {},
    setShareCadence: () => {},
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
  state.circleShare = { precision: null, cadence: null };
  state.identity = await generateIdentity();
  state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
  state.gen.at = Date.now();
  state.genRoster = new Set();
  state.pinned = new Map();
  internals.setupNet();
  await internals.setSharing(true);
  state.me = { lat: 40.785, lon: -73.968, acc: 5, ts: Date.now() };
}

async function read(level) {
  battery.level = level;
  await internals.sendLoc(true);
  await settle();
}

const card = () => internals.alertItems().find((i) => i.id === "own-battery");

test("a low battery offers the 5 minute cadence, and the button takes it", async () => {
  await sharing();
  await read(0.12);
  assert.ok(card(), "shown at 12%");
  assert.equal(card().title, "Your battery is at 12%");
  assert.deepEqual(card().actions.map((a) => a.label), ["Every 5 minutes", "Not now"]);

  await read(0.2);
  assert.equal(card(), undefined, "not at 20%");

  await read(0.12);
  state.sosActive = true;
  assert.equal(card(), undefined, "never during an SOS");
  state.sosActive = false;

  await card().actions[0].onClick();
  await settle();
  assert.equal(internals.shareCadence(), 300, "the circle now posts every 5 minutes");
  assert.equal(card(), undefined, "and the card has done its job");

  await internals.fireSos();
  await settle();
  assert.equal(internals.shareCadence(), 15, "an SOS still goes out every 15 seconds");
  await internals.doCheckin();
  await settle();
  assert.equal(internals.shareCadence(), 300);
});

test("Not now keeps it away until a reading above 25%", async () => {
  await sharing();
  await read(0.1);
  assert.ok(card());
  card().actions[1].onClick();
  assert.equal(card(), undefined);
  await read(0.08);
  assert.equal(card(), undefined, "a lower reading does not bring it back");
  await read(0.24);
  await read(0.1);
  assert.equal(card(), undefined, "nor does a charge that never passed 25%");
  await read(0.3);
  await read(0.1);
  assert.ok(card(), "a real charge and a new drop do");
});

test("no card while not sharing", async () => {
  await sharing();
  await read(0.3);
  await read(0.1);
  assert.ok(card());
  await internals.setSharing(false);
  assert.equal(card(), undefined, "not sharing, nothing to slow down");
});
