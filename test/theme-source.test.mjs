// A WebView built on the application context gets Android's default light theme, so Auto never went dark.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");
const res = (rel) => read(`android/app/src/main/res/${rel}`);
const kt = (name) => read(`android/app/src/main/kotlin/app/starlingmap/${name}`);

const parentOf = (xml) => xml.match(/<style name="Theme\.Starling" parent="([^"]+)"/)?.[1];

test("the wrapper theme is light by day and dark at night", () => {
  assert.equal(parentOf(res("values/themes.xml")), "android:Theme.Material.Light.NoActionBar");
  assert.equal(parentOf(res("values-night/themes.xml")), "android:Theme.Material.NoActionBar");
  assert.match(res("values/themes.xml"), /windowLightStatusBar">true</);
  assert.match(res("values-night/themes.xml"), /windowLightStatusBar">false</);
  const color = (xml, name) => xml.match(new RegExp(`<color name="${name}">(#[0-9a-f]{6})<`))?.[1];
  assert.equal(color(res("values/colors.xml"), "starling_bg"), "#f4f6fb");
  assert.equal(color(res("values-night/colors.xml"), "starling_bg"), "#0a0d14");
  for (const name of ["starling_fg", "starling_fg_dim"]) {
    assert.ok(color(res("values/colors.xml"), name) && color(res("values-night/colors.xml"), name), `${name} in both`);
  }
});

test("the WebView is built on the app theme, not on the bare application context", () => {
  const host = kt("PageHost.kt");
  assert.match(host, /WebView\(ContextThemeWrapper\(app, R\.style\.Theme_Starling\)\)/);
  assert.doesNotMatch(host, /WebView\(app\)/);
});

test("Auto asks the wrapper for the phone's dark mode and hears when it changes", () => {
  const main = read("app/js/main.js");
  assert.match(main, /if \(typeof n\?\.systemDark === "function"\) return !n\.systemDark\(\);/);
  assert.match(main, /return t === "auto" \? \(systemLight\(\) \? "light" : "dark"\) : t;/);
  assert.match(main, /globalThis\.__starlingScheme = onSchemeChange;/);
  const activity = kt("MainActivity.kt");
  assert.match(activity, /override fun onConfigurationChanged\(newConfig: Configuration\) \{[^}]*PageHost\.schemeChanged\(\)/);
  assert.match(activity, /override fun onStart\(\) \{[^}]*PageHost\.schemeChanged\(\)/);
  assert.match(kt("StarlingBridge.kt"), /fun systemDark\(\): Boolean =[\s\S]{0,120}UI_MODE_NIGHT_MASK\) ==[\s\S]{0,80}UI_MODE_NIGHT_YES/);
});

test("the bar icons follow the page's theme, on a window opened later too", () => {
  const main = read("app/js/main.js");
  const apply = main.slice(main.indexOf("function applyTheme()"), main.indexOf("const onSchemeChange"));
  assert.match(apply, /native\(\)\?\.setBarsLight\?\.\(t === "light"\)/);
  const activity = kt("MainActivity.kt");
  assert.match(activity, /isAppearanceLightStatusBars = light/);
  assert.match(activity, /isAppearanceLightNavigationBars = light/);
  assert.match(activity, /setContentView\(webView\)\s*PageHost\.barsLight\?\.let \{ setBarsLight\(it\) \}/);
  assert.match(kt("StarlingBridge.kt"), /fun setBarsLight\(light: Boolean\) \{\s*barsLight = light\s*ui \{ it\.setBarsLight\(light\) \}/);
});
