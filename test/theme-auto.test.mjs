// The wrapper's WebView fixes prefers-color-scheme when it is built, so Auto asks the bridge.
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
const { api } = await loadApp(harness);

test.after(() => harness.stopTimers());

test("Auto takes the phone's dark mode from the wrapper and repaints when it says it changed", async () => {
  let dark = false;
  const bars = [];
  globalThis.StarlingNative = { systemDark: () => dark, setBarsLight: (light) => bars.push(light) };
  try {
    await api.setSetting("theme", "auto");
    await settle();
    assert.equal(document.documentElement.dataset.theme, "light", "the harness's matchMedia says dark; the bridge wins");
    assert.equal(bars.at(-1), true, "dark bar icons on a light page");

    dark = true;
    globalThis.__starlingScheme();
    assert.equal(document.documentElement.dataset.theme, "dark");
    assert.equal(bars.at(-1), false);

    await api.setSetting("theme", "light");
    globalThis.__starlingScheme();
    assert.equal(document.documentElement.dataset.theme, "light", "a chosen theme ignores the phone");
    assert.equal(bars.at(-1), true);
  } finally {
    delete globalThis.StarlingNative;
  }
});

test("without the wrapper method Auto still reads prefers-color-scheme", async () => {
  globalThis.StarlingNative = {};
  try {
    await api.setSetting("theme", "auto");
    await settle();
    assert.equal(document.documentElement.dataset.theme, "dark", "the harness's matchMedia does not match light");
  } finally {
    delete globalThis.StarlingNative;
  }
});
