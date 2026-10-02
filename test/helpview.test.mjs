// helpview.js is imported before the page stub exists, so it does not boot itself here.
import test from "node:test";
import assert from "node:assert/strict";

const { helperLines } = await import("../app/js/helpview.js");
const { setLocale } = await import("../app/js/i18n.js");
setLocale("en");

const { installDom, loadApp, settle } = await import("./dom-harness.mjs");

test("helperLines gives coordinates to five places and a map link for them", () => {
  const out = helperLines({ lat: 40.7712, lon: -73.974 }, { now: 0 });
  assert.equal(out.coords, "40.77120, -73.97400");
  assert.match(out.coords, /^-?\d+\.\d{5}, -?\d+\.\d{5}$/);
  assert.equal(out.mapsUrl, "https://www.openstreetmap.org/?mlat=40.77120&mlon=-73.97400#map=17/40.77120/-73.97400");
  const south = helperLines({ lat: -33.8688, lon: 151.2093 }, { now: 0 });
  assert.equal(south.coords, "-33.86880, 151.20930");
});

test("helperLines says nothing it does not know", () => {
  const out = helperLines({ name: "Ana" }, { now: 0 });
  assert.deepEqual(out, { coords: "", mapsUrl: "", acc: "", bat: "", expires: "" });
});

test("helperLines carries accuracy and battery only when the post did", () => {
  const both = helperLines({ lat: 1, lon: 2, acc: 12, bat: 0.42 }, { now: 0 });
  assert.equal(both.acc, "Accurate to about 12 m");
  assert.equal(both.bat, "Phone battery 42%");
  const neither = helperLines({ lat: 1, lon: 2 }, { now: 0 });
  assert.equal(neither.acc, "");
  assert.equal(neither.bat, "");
  assert.equal(helperLines({ lat: 1, lon: 2, bat: 0 }, { now: 0 }).bat, "Phone battery 0%", "an empty battery is still a reading");
});

test("helperLines says how long the link works, and nothing once it has run out", () => {
  const now = Date.UTC(2026, 9, 2, 12, 0);
  const expiresAt = now + 6 * 60 * 60 * 1000;
  const out = helperLines({ lat: 1, lon: 2 }, { now, expiresAt });
  assert.match(out.expires, /^Link works until \d{1,2}:\d{2}/);
  assert.equal(helperLines({ lat: 1, lon: 2 }, { now: expiresAt, expiresAt }).expires, "");
  assert.equal(helperLines({ lat: 1, lon: 2 }, { now }).expires, "");
});

test("the beacon post carries the battery level a circle post does", async () => {
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
  navigator.getBattery = async () => ({ level: 0.42 });
  const { internals, api } = await loadApp(harness);
  const state = internals.state;
  const { openGeneration } = await import("../app/js/rekey.js");
  const { epochAt } = await import("../app/js/ratchet.js");
  const { generateIdentity, newSeed, openMessage, parseBeaconFragment, deriveHelpChannelId, deriveHelpEncKey } =
    await import("../app/js/crypto.js");
  const { b64uDecode } = await import("../app/js/wire.js");

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
  state.demo = false;
  state.locked = false;
  state.identity = await generateIdentity();
  state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
  state.gen.at = Date.now();
  state.genRoster = new Set();
  state.pinned = new Map();
  internals.setupNet();
  await internals.setSharing(true);
  state.me = { lat: 40.7712, lon: -73.974, acc: 9, ts: Date.now() };

  const posts = [];
  harness.onFetch(async (url, init) => {
    if (init?.method === "POST") posts.push({ url, body: JSON.parse(init.body) });
    return undefined;
  });
  try {
    await internals.fireSos();
    for (let i = 0; i < 50 && !(api.beaconViewers()[0]?.link && posts.some((p) => !p.url.includes(state.gen.channelId))); i++) {
      await settle(20);
    }
    const link = api.beaconViewers()[0]?.link;
    assert.ok(link, "the SOS minted a help link");
    const { secret, ownerId } = parseBeaconFragment(`#${link.split("#")[1]}`);
    const helpChannel = await deriveHelpChannelId(secret);
    const helpKey = await deriveHelpEncKey(secret, ["decrypt"]);

    const circlePost = posts.filter((p) => p.url.includes(`/f/${state.gen.channelId}/`)).at(-1).body;
    const circleKey = await state.gen.ratchet.keyFor(circlePost.e, state.identity.memberId, circlePost.ts);
    const circle = await openMessage(circleKey, state.gen.channelId, state.identity.memberId, circlePost.e, circlePost.ts, b64uDecode(circlePost.n), b64uDecode(circlePost.c));
    const beaconPost = posts.filter((p) => p.url.includes(`/f/${helpChannel}/`)).at(-1)?.body;
    assert.ok(beaconPost, "the beacon posted to the helper's channel");
    const help = await openMessage(helpKey, helpChannel, ownerId, beaconPost.e, beaconPost.ts, b64uDecode(beaconPost.n), b64uDecode(beaconPost.c));

    assert.equal(circle.bat, 0.42);
    assert.equal(help.bat, 0.42, "the helper sees the same battery the circle does");
    assert.equal(help.acc, 9);
  } finally {
    harness.onFetch(null);
    state.sosActive = false;
    if (state.sharing) await internals.setSharing(false);
    delete globalThis.StarlingNative;
    harness.stopTimers();
  }
});
