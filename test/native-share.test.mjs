// Android System WebView has no navigator.share, so the wrapper's bridge opens the share sheet instead.
import test from "node:test";
import assert from "node:assert/strict";

import { installDom } from "./dom-harness.mjs";

const harness = installDom();
const { shareLink } = await import("../app/js/ui.js");

test.after(() => harness.stopTimers());

const LINK = "https://starlingmap.app/#h=abc";

function stubClipboard() {
  const writes = [];
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: async (s) => writes.push(s) },
  });
  return writes;
}

test("the wrapper's share sheet gets the whole line, and the clipboard is left alone", async () => {
  const writes = stubClipboard();
  const shared = [];
  globalThis.StarlingNative = { shareText: (text) => (shared.push(text), true) };
  try {
    await shareLink(LINK, "Follow my location:", "Help link copied");
  } finally {
    delete globalThis.StarlingNative;
  }
  assert.deepEqual(shared, [`Follow my location: ${LINK}`]);
  assert.deepEqual(writes, [], "the native path never writes the clipboard");
});

test("with no window for the sheet, the link is copied instead", async () => {
  const writes = stubClipboard();
  globalThis.StarlingNative = { shareText: () => false };
  try {
    await shareLink(LINK, "Follow my location:", "Help link copied");
  } finally {
    delete globalThis.StarlingNative;
  }
  assert.deepEqual(writes, [LINK]);
});

test("an older wrapper without the method copies, as before", async () => {
  const writes = stubClipboard();
  globalThis.StarlingNative = {};
  try {
    await shareLink(LINK, "Join my circle on Starling:", "Invite link copied");
  } finally {
    delete globalThis.StarlingNative;
  }
  assert.deepEqual(writes, [LINK]);
});

test("the bridge answers false with no window on screen, caps the text, and starts a chooser", async () => {
  const { readFileSync } = await import("node:fs");
  const kt = (name) =>
    readFileSync(new URL(`../android/app/src/main/kotlin/app/starlingmap/${name}`, import.meta.url), "utf8");
  const bridge = kt("StarlingBridge.kt");
  assert.match(bridge, /fun shareText\(text: String\): Boolean \{\s*val a = activity \?: return false\s*if \(!PageHost\.windowShown \|\| PageHost\.activity !== a\) return false\s*val body = text\.take\(2000\)/);
  assert.match(
    kt("MainActivity.kt"),
    /Intent\(Intent\.ACTION_SEND\)\.setType\("text\/plain"\)\.putExtra\(Intent\.EXTRA_TEXT, text\)[\s\S]{0,80}Intent\.createChooser\(send, null\)/,
  );
});
