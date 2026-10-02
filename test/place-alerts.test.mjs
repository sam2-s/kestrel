// Per-place alert choices through the real roster and checkAlerts.
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

test.after(() => {
  delete globalThis.StarlingNative;
  harness.stopTimers();
});

const BASE = { lat: 40.0, lon: -75.0 };
const north = (m) => ({ lat: BASE.lat + m / 111320, lon: BASE.lon });

async function circleWith(places) {
  state.demo = false;
  state.locked = false;
  state.lock = null;
  state.settings = { ...state.settings, placeAlerts: true };
  state.identity = await generateIdentity();
  state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
  state.gen.at = Date.now();
  state.genRoster = new Set();
  state.pinned = new Map();
  internals.setupNet();
  internals.resetMemberAlerts();
  state.places = places;
  await internals.savePlaces();
}

// Far away, into the place, and back out; returns the place notifications.
async function walk(who) {
  const calls = [];
  globalThis.StarlingNative = {
    windowShown: () => false,
    notify: (title, body, tag) => {
      if (tag === `place-${who.memberId}`) calls.push(title);
    },
    cancelNotify: () => {},
  };
  const t0 = Date.now();
  const realNow = Date.now;
  const step = async (pos, ts) => {
    const gen = state.gen;
    const e = epochAt(ts);
    const key = await gen.ratchet.keyFor(e, who.memberId, ts);
    const sealed = await sealMessage(key, gen.channelId, who.memberId, e, ts, {
      v: 2,
      ts,
      t: "loc",
      name: "Juno",
      lat: pos.lat,
      lon: pos.lon,
      acc: 5,
      mode: "precise",
    });
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
    Date.now = () => ts + 500;
    try {
      internals.checkAlerts();
    } finally {
      Date.now = realNow;
    }
  };
  await step(north(2000), t0);
  await step(BASE, t0 + 60_000);
  const atPlace = internals.placeTracker.placeFor(who.memberId)?.name ?? null;
  await step(north(2000), t0 + 210_000);
  return { calls, atPlace };
}

const HOME = { id: "aaaaaaaa", name: "Home", lat: BASE.lat, lon: BASE.lon, radius: 250 };

test("an arrive-only place announces arrival and not departure", async () => {
  await circleWith([{ ...HOME, alerts: "arrive" }]);
  const { calls } = await walk(await generateIdentity());
  assert.deepEqual(calls, ["Juno arrived at Home"]);

  await circleWith([HOME]);
  const both = await walk(await generateIdentity());
  assert.deepEqual(both.calls, ["Juno arrived at Home", "Juno left Home"], "a place with no choice still says both");
});

test("an off place announces nothing but the member still shows at it", async () => {
  await circleWith([{ ...HOME, alerts: "off" }]);
  const { calls, atPlace } = await walk(await generateIdentity());
  assert.deepEqual(calls, []);
  assert.equal(atPlace, "Home", "the At Home line stays true with the alerts off");
});
