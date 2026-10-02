// What the service pushes besides positions, the answer the page owes each
// push, and "is anybody looking", which visibility alone no longer answers.
import test from "node:test";
import assert from "node:assert/strict";

import { pageShown } from "../app/js/env.js";
import { startWatch } from "../app/js/geo.js";

function withGlobals({ visibility, native }, fn) {
  const prevDoc = Object.getOwnPropertyDescriptor(globalThis, "document");
  const prevNative = Object.getOwnPropertyDescriptor(globalThis, "StarlingNative");
  globalThis.document = { visibilityState: visibility };
  if (native === undefined) delete globalThis.StarlingNative;
  else globalThis.StarlingNative = native;
  try {
    return fn();
  } finally {
    if (prevDoc) Object.defineProperty(globalThis, "document", prevDoc);
    else delete globalThis.document;
    if (prevNative) Object.defineProperty(globalThis, "StarlingNative", prevNative);
    else delete globalThis.StarlingNative;
  }
}

test("on the web, shown is just visible", () => {
  assert.equal(withGlobals({ visibility: "visible", native: undefined }, pageShown), true);
  assert.equal(withGlobals({ visibility: "hidden", native: undefined }, pageShown), false);
});

test("in the wrapper, a page made visible to keep it from freezing is not shown", () => {
  const nudged = { windowShown: () => false };
  assert.equal(withGlobals({ visibility: "visible", native: nudged }, pageShown), false);
  const open = { windowShown: () => true };
  assert.equal(withGlobals({ visibility: "visible", native: open }, pageShown), true);
  assert.equal(withGlobals({ visibility: "hidden", native: open }, pageShown), false, "hidden is hidden whatever the window says");
});

test("an older wrapper, or one whose answer throws, falls back to the page's own visibility", () => {
  assert.equal(withGlobals({ visibility: "visible", native: { platform: () => "android" } }, pageShown), true);
  const broken = {
    windowShown() {
      throw new Error("bridge gone");
    },
  };
  assert.equal(withGlobals({ visibility: "visible", native: broken }, pageShown), true);
});

function watch({ throwOnStart = false } = {}) {
  const seen = { fixes: [], errors: [], signals: [], after: 0 };
  const native = {
    startLocation() {
      if (throwOnStart) throw new Error("no window");
    },
    stopLocation() {},
  };
  globalThis.StarlingNative = native;
  const stop = startWatch(
    (f) => seen.fixes.push(f),
    (e) => seen.errors.push(e),
    { onSignal: (s) => seen.signals.push(s), afterEach: () => seen.after++ },
  );
  const push = (obj) => globalThis.__starlingFix?.(typeof obj === "string" ? obj : JSON.stringify(obj));
  return { seen, push, stop };
}

test("a tick and the location switch arrive as signals, not as fixes or errors", () => {
  const { seen, push, stop } = watch();
  try {
    push({ tick: true });
    push({ paused: "location-off" });
    push({ paused: "" });
    assert.deepEqual(seen.signals, [{ tick: true }, { paused: "location-off" }, { paused: null }]);
    assert.equal(seen.fixes.length, 0);
    assert.equal(seen.errors.length, 0);
  } finally {
    stop();
    delete globalThis.StarlingNative;
  }
});

test("a stop carries how it happened, and an unmarked one is the notification's", () => {
  const { seen, push, stop } = watch();
  try {
    push({ stopped: true, route: "system" });
    push({ stopped: true });
    assert.equal(seen.errors.length, 2);
    assert.equal(seen.errors[0].route, "system");
    assert.equal(seen.errors[0].native, true);
    assert.equal(seen.errors[0].stopped, true);
    assert.equal(seen.errors[1].route, "notif");
  } finally {
    stop();
    delete globalThis.StarlingNative;
  }
});

test("every push is answered, including one the page could not make sense of or choked on", () => {
  const seen = { after: 0 };
  globalThis.StarlingNative = { startLocation() {}, stopLocation() {} };
  const stop = startWatch(
    () => {
      throw new Error("render blew up");
    },
    () => {},
    { afterEach: () => seen.after++ },
  );
  try {
    globalThis.__starlingFix("not json at all");
    assert.throws(() => globalThis.__starlingFix(JSON.stringify({ lat: 1, lon: 2, ts: 3 })), /render blew up/);
    globalThis.__starlingFix(JSON.stringify({ tick: true }));
    assert.equal(seen.after, 3, "the wrapper hears back after each one, or it would read the page as frozen");
  } finally {
    stop();
    delete globalThis.StarlingNative;
  }
});

test("a start the bridge refuses is a native error, so the share stops instead of waiting forever", () => {
  const { seen, stop } = watch({ throwOnStart: true });
  try {
    assert.equal(seen.errors.length, 1);
    assert.equal(seen.errors[0].native, true);
    assert.equal(typeof globalThis.__starlingFix, "undefined", "and nothing is left listening");
  } finally {
    stop();
    delete globalThis.StarlingNative;
  }
});
