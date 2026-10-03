// A rebrand fails quietly: a stale string survives in some corner of the UI,
// an icon path outlives the file it named, a theme-color keeps the old hue.
// Manual re-reads miss them. These assertions pin the brand so the next
// rename or palette change either completes or fails the suite.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const read = (rel) => readFileSync(join(root, rel), "utf8");
const app = (rel) => join(root, "app", rel);

// The canonical origin and the wire labels are facts about the deployed
// service, not branding: they move when the domain and the protocol move.
// Everything else that says "starling" where a person can read it is a bug.
const ORIGIN_OK = /starlingmap\.app/;
const PROTOCOL_JS = new Set([
  "env.js", // canonical origin, ios scheme, relay normalization
  "wire.js", // starling/v2 label prefixes
  "net.js", // relay endpoint paths and health wording
  "roster.js", // starling/v2 roster labels
  "qrscan.js", // starling: invite scheme
  "lock.js", // starling/v1 prf and bio-wrap kdf labels
]);

test("no page the user reads says Starling", () => {
  const pages = ["app/index.html", "app/privacy.html", "app/help.html"];
  for (const page of pages) {
    const html = read(page);
    const hits = html.split("\n").map((l, i) => [i + 1, l]).filter(([, l]) => /starling/i.test(l));
    for (const [line, text] of hits) {
      // privacy.html names the upstream-hosted relay as a fact; that sentence
      // stays honest even under the new name.
      assert.ok(
        page === "app/privacy.html" && ORIGIN_OK.test(text),
        `${page}:${line} says starling: ${text.trim()}`,
      );
    }
  }
});

test("app strings carry the Kestrel name", () => {
  const index = read("app/index.html");
  assert.match(index, /<title>[^<]*Kestrel/i);
  const manifest = JSON.parse(read("app/manifest.webmanifest"));
  assert.match(manifest.name, /Kestrel/i);
  assert.match(manifest.short_name, /Kestrel/i);
  assert.doesNotMatch(manifest.name + manifest.short_name, /starling/i);
});

test("no script outside the protocol layer says starling", () => {
  const files = readdirSync(app("js")).filter((f) => f.endsWith(".js"));
  for (const file of files) {
    if (PROTOCOL_JS.has(file)) continue;
    const src = read(join("app/js", file));
    const idx = src.search(/starling/i);
    if (idx === -1) continue;
    const line = src.slice(0, idx).split("\n").length;
    const text = src.split("\n")[line - 1].trim();
    // A comment naming the upstream project is attribution, not user copy.
    const comment = /^\s*(\/\/|\*|\/\*)/.test(text);
    assert.ok(comment, `app/js/${file}:${line} says starling: ${text}`);
  }
});

test("downloads and stashes are named for Kestrel", () => {
  const ui = read("app/js/ui.js");
  assert.match(ui, /"kestrel-data\.json"/);
  assert.doesNotMatch(ui, /starling-data\.json/);
  const help = read("app/js/helpview.js");
  assert.match(help, /"kestrel-beacon"/);
  assert.doesNotMatch(help, /starling-beacon/);
});

test("every icon the page, worker and manifest name exists", () => {
  const refs = new Set();
  for (const file of ["app/index.html", "app/privacy.html", "app/help.html"]) {
    const html = read(file);
    for (const m of html.matchAll(/(?:src|href)="(icons\/[^"]+)"/g)) refs.add(m[1]);
  }
  const manifest = JSON.parse(read("app/manifest.webmanifest"));
  for (const icon of manifest.icons) refs.add(icon.src.replace(/^\//, ""));
  const sw = read("app/sw.js");
  for (const m of sw.matchAll(/"(\/icons\/[^"]+)"/g)) refs.add(m[1].replace(/^\//, ""));
  assert.ok(refs.size >= 5, "expected a spread of icon references");
  for (const rel of refs) {
    assert.ok(existsSync(app(rel)), `missing icon: app/${rel}`);
  }
});

test("share and canonical links point at the new home", () => {
  const index = read("app/index.html");
  for (const m of index.matchAll(/<(?:meta[^>]+(?:og:image|twitter:image|og:url)[^>]+|link[^>]+canonical[^>]+)>/g)) {
    assert.doesNotMatch(m[0], /starlingmap\.app/, `old origin in ${m[0]}`);
  }
  const about = index.match(/id="about-site"[^>]*href="([^"]+)"/);
  assert.ok(about, "about-site link present");
  assert.match(about[1], /github\.com\/sam2-s\/kestrel/, "about-site names this repo");
});

test("the service worker cache version is a Kestrel build", () => {
  const sw = read("app/sw.js");
  const version = sw.match(/^const VERSION = "([^"]+)";$/m);
  assert.ok(version, "VERSION constant present");
  assert.match(version[1], /^kestrel-v\d+$/, "cache key is branded");
});

test("both themes define the palette and the old one is gone", () => {
  const tokens = read("app/css/tokens.css");
  for (const key of [
    "--accent", "--accent-2", "--accent-grad", "--accent-ink",
    "--live", "--warn", "--sos", "--stale",
    "--bg", "--bg-1", "--bg-2", "--bg-3",
    "--ink", "--ink-2", "--ink-3", "--line", "--glass", "--glass-border",
  ]) {
    assert.ok(new RegExp(`${key}:`).test(tokens), `${key} defined`);
  }
  // Dark ships as :root, light overrides its surfaces; both must exist.
  assert.match(tokens, /--bg: #12100e;/);
  assert.match(tokens, /:root\[data-theme="light"\][\s\S]*--bg: #faf7f2;/);
  const upstream = /#2dd4bf|#8b5cf6|#60a5fa|#0a0d14|#101522|#171e30/;
  const scan = [
    ...readdirSync(app("css")).map((f) => join("app/css", f)),
    "app/index.html", "app/privacy.html", "app/help.html",
    "app/manifest.webmanifest", "app/js/main.js",
  ];
  for (const file of scan) {
    assert.doesNotMatch(read(file), upstream, `${file} carries an old palette colour`);
  }
});

test("the android launcher faces match the web brand", () => {
  const densityDir = (d) => `android/app/src/main/res/mipmap-${d}`;
  for (const d of ["mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"]) {
    assert.ok(existsSync(join(root, densityDir(d), "ic_launcher_fg.png")), `${d} foreground`);
  }
  const adaptive = read("android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml");
  assert.match(adaptive, /@mipmap\/ic_launcher_fg/);
  assert.match(adaptive, /@color\/kestrel_bg/);
  // The platform accent is whatever the dark theme's accent is, so the two
  // cannot drift apart.
  const accent = read("app/css/tokens.css").match(/--accent: (#[0-9a-f]{6});/)[1];
  for (const theme of ["values/themes.xml", "values-night/themes.xml"]) {
    const xml = read(`android/app/src/main/res/${theme}`);
    assert.ok(xml.includes(accent), `${theme} colorAccent is ${accent}`);
  }
});

test("install tooling references the Kestrel artwork and defaults", () => {
  const ios = read("tools/icons-ios.sh");
  assert.match(ios, /app\/icons\/kestrel\.svg/);
  assert.doesNotMatch(ios, /starling/);
  assert.ok(existsSync(app("icons/kestrel.svg")), "source svg exists");
  for (const file of ["relay/deploy.sh", "relay/wrangler.toml", "tools/release-android.sh"]) {
    assert.doesNotMatch(read(file), /munzzyy|starling/i, `${file} defaults`);
  }
});
