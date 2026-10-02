// Kotlin read as source; the emulator check for Do Not Disturb is in the commit that added it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const kt = (name) =>
  readFileSync(new URL(`../android/app/src/main/kotlin/app/starlingmap/${name}`, import.meta.url), "utf8");
const ui = () => readFileSync(new URL("../app/js/ui.js", import.meta.url), "utf8");

function fn(src, name) {
  const at = src.search(new RegExp(`fun ${name}\\([^)]*\\)(: [\\w?<>, ]+)? \\{`));
  assert.ok(at >= 0, `fun ${name} exists`);
  const open = src.indexOf("{", at);
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(at, i + 1);
  }
  throw new Error(`unbalanced ${name}`);
}

const constant = (src, name) => src.match(new RegExp(`const val ${name} = "([^"]+)"`))?.[1];

test("the SOS channel plays as an alarm, under an id the ringtone channel never had", () => {
  const main = kt("MainActivity.kt");
  const id = constant(main, "SOS_CHANNEL");
  assert.ok(id, "SOS_CHANNEL is a string constant");
  assert.notEqual(id, "events_sos", "a channel's sound attributes are fixed once created, so the id has to change");
  assert.equal(constant(main, "OLD_SOS_CHANNEL"), "events_sos");
  const channel = fn(kt("Events.kt"), "buildChannel");
  assert.match(channel, /setUsage\(AudioAttributes\.USAGE_ALARM\)/);
  assert.doesNotMatch(channel, /USAGE_NOTIFICATION_RINGTONE/);
  assert.match(channel, /vibrationPattern = SOS_VIBRATION/, "the pulsing pattern stays");
});

test("an urgent notification is an alarm, posted on the new channel after the old one is gone", () => {
  const events = kt("Events.kt");
  const show = fn(events, "show");
  assert.match(show, /if \(urgent\) ensureSosChannel\(ctx\)/);
  assert.match(show, /if \(urgent\) \{[^}]*setCategory\(NotificationCompat\.CATEGORY_ALARM\)/);
  assert.equal((events.match(/CATEGORY_ALARM/g) || []).length, 1, "routine events stay out of the alarm category");
  assert.match(fn(events, "post"), /if \(urgent\) R\.string\.notif_sos_text else R\.string\.notif_locked_text/, "the text stays the generic line");
  const ensure = fn(events, "ensureSosChannel");
  assert.ok(
    ensure.indexOf("deleteNotificationChannel(MainActivity.OLD_SOS_CHANNEL)") <
      ensure.indexOf("createNotificationChannel(buildChannel(ctx, MainActivity.SOS_CHANNEL, true))"),
  );
});

test("the panic wipe deletes both SOS channels", () => {
  const wipe = fn(kt("Wipe.kt"), "everything");
  assert.match(wipe, /MainActivity\.SOS_CHANNEL,/);
  assert.match(wipe, /MainActivity\.OLD_SOS_CHANNEL,/);
});

test("Settings offers the channel page only where the wrapper has it", () => {
  assert.match(kt("StarlingBridge.kt"), /fun openSosChannelSettings\(\) \{\s*ui \{ it\.openSosChannelSettings\(\) \}/);
  const open = fn(kt("MainActivity.kt"), "openSosChannelSettings");
  assert.match(open, /val channel = Events\.ensureSosChannel\(this\)/, "the channel exists before its page opens");
  assert.match(open, /ACTION_CHANNEL_NOTIFICATION_SETTINGS[\s\S]*EXTRA_CHANNEL_ID, channel/);
  assert.match(ui(), /if \(typeof native\(\)\?\.openSosChannelSettings === "function"\) \{\s*const box/);
});
