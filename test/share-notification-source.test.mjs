// Kotlin read as source; the emulator check for the swiped notification is in the commit that added it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const kt = (name) =>
  readFileSync(new URL(`../android/app/src/main/kotlin/app/starlingmap/${name}`, import.meta.url), "utf8");
const manifest = () => readFileSync(new URL("../android/app/src/main/AndroidManifest.xml", import.meta.url), "utf8");

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

test("the sharing notification carries a delete intent back to the service", () => {
  const build = fn(kt("LocationService.kt"), "buildNotification");
  assert.match(
    build,
    /val swiped = PendingIntent\.getService\(\s*this,\s*\d+,\s*Intent\(this, LocationService::class\.java\)\.setAction\(ACTION_REPOST\),\s*PendingIntent\.FLAG_IMMUTABLE,\s*\)/,
  );
  assert.match(build, /\.setOngoing\(true\)\s*\.setDeleteIntent\(swiped\)/);
  assert.match(manifest(), /android:name="\.LocationService"\s*android:exported="false"/, "nothing outside the app can send it");
});

test("a swipe puts the notification back only while the share is live, and starts nothing otherwise", () => {
  const start = fn(kt("LocationService.kt"), "onStartCommand");
  const repost = start.slice(start.indexOf("if (intent?.action == ACTION_REPOST)"));
  assert.ok(start.indexOf("ACTION_STOP") < start.indexOf("ACTION_REPOST"), "Stop is handled first and untouched");
  assert.match(repost, /^if \(intent\?\.action == ACTION_REPOST\) \{[\s\S]*?if \(live\) \{\s*runCatching \{[^}]*notify\(NOTIF_ID, buildNotification\(\)\)/);
  assert.match(repost, /\} else if \(!running\) \{[^}]*stopAsked = true\s*stopSelf\(startId\)\s*\}\s*return START_NOT_STICKY\s*\}/);
  assert.ok(
    repost.indexOf("return START_NOT_STICKY") < repost.indexOf("startForeground"),
    "the repost path returns before anything that starts a share",
  );
});
