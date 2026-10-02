// munzzyy/starling#6: only a stop the person chose asks for a reminder, and a share or a wipe takes it back.
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
const { generateIdentity, newSeed } = await import("../app/js/crypto.js");

test.after(() => harness.stopTimers());

const HOUR = 3_600_000;
let calls = [];

async function sharing(reminderMs) {
  calls = [];
  globalThis.StarlingNative = {
    startLocation: () => calls.push(["start"]),
    stopLocation: () => calls.push(["stop"]),
    clearStopRecord: () => {},
    windowShown: () => true,
    pulse: () => {},
    remindShareIn: (ms) => calls.push(["remind", ms]),
    cancelShareReminder: () => calls.push(["cancel"]),
  };
  internals.resetShareResumeGuard();
  state.demo = false;
  state.locked = false;
  state.lock = null;
  state.sosActive = false;
  state.settings = { ...state.settings, shareReminder: reminderMs };
  state.identity = state.identity || (await generateIdentity());
  if (!state.gen) {
    state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
    state.gen.at = Date.now();
    state.genRoster = new Set();
    state.pinned = new Map();
  }
  if (state.sharing) await internals.setSharing(false);
  internals.setupNet();
  calls = [];
  await internals.setSharing(true);
  assert.equal(state.sharing, true);
}

const reminders = () => calls.filter((c) => c[0] === "remind");

test("a fresh install never reminds", () => {
  assert.equal(internals.state.settings.shareReminder, 0);
});

test("starting a share takes back any reminder", async () => {
  await sharing(4 * HOUR);
  assert.deepEqual(calls[0], ["cancel"], "cancelled before anything else starts");
  await internals.setSharing(false);
});

test("a stop the person chose asks for the reminder after the chosen time", async () => {
  await sharing(4 * HOUR);
  await internals.setSharing(false);
  assert.deepEqual(reminders(), [["remind", 4 * HOUR]]);
});

test("Never asks for nothing", async () => {
  await sharing(0);
  await internals.setSharing(false);
  assert.deepEqual(reminders(), []);
});

test("a stop Android made asks for nothing, since that share comes back by itself", async () => {
  await sharing(HOUR);
  await internals.setSharing(false, { keepArmed: true });
  assert.deepEqual(reminders(), []);
});

test("the panic wipe takes back a reminder before it wipes", async () => {
  await sharing(HOUR);
  await internals.setSharing(false);
  calls = [];
  globalThis.StarlingNative.panicWipe = () => calls.push(["wipe"]);
  await internals.panic();
  const at = (name) => calls.findIndex((c) => c[0] === name);
  assert.ok(at("cancel") >= 0, "panic cancels the reminder");
  assert.ok(at("cancel") < at("wipe"), "before the wipe kills the process");
});

test("the Kotlin side: an inexact alarm, a private receiver, and silence while a share runs", async () => {
  const { readFileSync } = await import("node:fs");
  const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");
  const kt = (name) => read(`android/app/src/main/kotlin/app/starlingmap/${name}`);
  const manifest = read("android/app/src/main/AndroidManifest.xml");
  assert.doesNotMatch(manifest, /EXACT_ALARM/);
  assert.match(manifest, /<receiver\s+android:name="\.ShareReminderReceiver"\s+android:exported="false"\s*\/>/);
  const reminder = kt("ShareReminder.kt");
  // A short delay takes the plain alarm, whose 75% runs late by less than the 10 minute window.
  assert.match(
    reminder,
    /if \(delay \/ 4 \* 3 < WINDOW_MS\) \{\s*am\.set\(AlarmManager\.ELAPSED_REALTIME_WAKEUP, at, pending\(ctx\)\)\s*\} else \{\s*am\.setWindow\(AlarmManager\.ELAPSED_REALTIME_WAKEUP, at, WINDOW_MS, pending\(ctx\)\)/,
  );
  assert.match(reminder, /WINDOW_MS = 10 \* 60_000L/);
  assert.doesNotMatch(reminder, /setExact|setAlarmClock/);
  assert.match(reminder, /override fun onReceive\(context: Context, intent: Intent\) \{\s*if \(LocationService\.running\) return\s*Events\.postShareOff\(context\)/);
  assert.match(kt("Events.kt"), /fun postShareOff\(ctx: Context\) =\s*show\(ctx, R\.string\.notif_remind_title, R\.string\.notif_remind_text, ShareReminder\.TAG, false\)/);
  assert.match(kt("Wipe.kt"), /runCatching \{ ShareReminder\.cancel\(ctx\) \}/);
  for (const dir of ["values", "values-es", "values-de", "values-fr", "values-pt"]) {
    const strings = read(`android/app/src/main/res/${dir}/strings.xml`);
    assert.match(strings, /name="notif_remind_title"/, dir);
    assert.match(strings, /name="notif_remind_text"/, dir);
  }
});
