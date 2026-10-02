// Android 9: the build targets it, the wrapper turns away a WebView too old
// for the page (Ed25519 keys from newer phones need 137) and says why, and
// the two Android 10 calls have their Android 9 counterparts.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const KT = "android/app/src/main/kotlin/app/starlingmap/";
const KEYS = ["webview_title", "webview_too_old", "webview_missing", "android9_title", "android9_body"];

// Windows checkouts carry CRLF, and these checks match on line ends.
const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8").replace(/\r\n/g, "\n");
const RES = "android/app/src/main/res/";

test("the build installs on Android 9", () => {
  assert.match(read("android/app/build.gradle.kts"), /^\s*minSdk = 28$/m);
});

test("every new string has a Spanish version with the same placeholders", () => {
  const en = read(RES + "values/strings.xml");
  const es = read(RES + "values-es/strings.xml");
  const get = (xml, key) => xml.match(new RegExp(`<string name="${key}"[^>]*>([^<]*)</string>`))?.[1];
  for (const key of KEYS) {
    assert.ok(get(en, key), `values/${key}`);
    assert.ok(get(es, key), `values-es/${key}`);
  }
  for (const xml of [en, es]) {
    const tooOld = get(xml, "webview_too_old");
    assert.ok(tooOld.includes("%1$d") && tooOld.includes("%2$d"), "needs the minimum and the phone's version");
    assert.doesNotMatch(xml, /[\u2013\u2014]/);
  }
  assert.match(get(en, "android9_body"), /January 2022/);
  assert.match(get(es, "android9_body"), /enero de 2022/);
});

test("the WebView check runs before the page host builds one", () => {
  const src = read(KT + "MainActivity.kt");
  const gate = src.indexOf("if (!PageHost.alive && SystemCheck.blockIfWebViewTooOld(this)) return");
  const attach = src.indexOf("PageHost.attach(this)");
  const tor = src.indexOf("applyTorPref()\n");
  assert.ok(gate > 0 && gate < attach && gate < tor);
  assert.ok(src.indexOf("SystemCheck.noteAndroid9(this)") > attach);
});

test("release builds hold the Ed25519 floor; only debug builds drop to the parse floor", () => {
  const src = read(KT + "SystemCheck.kt");
  assert.match(src, /const val MIN_WEBVIEW = 137\b/);
  assert.match(src, /FLAG_DEBUGGABLE\) != 0\) MIN_WEBVIEW_DEBUG else MIN_WEBVIEW/);
  assert.match(src, /webview_too_old, min, major/);
});

test("the share service starts on Android 9 without a service type", () => {
  const src = read(KT + "LocationService.kt");
  assert.match(src, /ServiceCompat\.startForeground\(this, NOTIF_ID, buildNotification\(\), ServiceInfo\.FOREGROUND_SERVICE_TYPE_LOCATION\)/);
  assert.doesNotMatch(src, /^\s*startForeground\(/m);
});

test("the health check reads the location op on Android 9 too", () => {
  assert.match(
    read(KT + "Health.kt"),
    /SDK_INT >= Build\.VERSION_CODES\.Q\) \{\s*ops\.unsafeCheckOpNoThrow[^}]*\} else \{\s*@Suppress\("DEPRECATION"\)\s*ops\.checkOpNoThrow/,
  );
});
