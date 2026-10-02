// The safety number scan end to end, in headless Chromium with a fake camera.
// Chromium is told to serve a Y4M file as the camera; the file is a QR code
// of a pinned member's safety number, drawn with the in-house encoder; the
// page is the real one with the Android bridge stub planted the way
// test/e2e_wrapper.mjs plants it, so the scanner is on as it is in the app.
//
// Checked: the sheet gets a live stream, the code reads, the verdict offers
// the verified mark, the mark lands on the member's row, every camera track
// is ended afterwards, the page's CSP let the stream play as it stands, and
// nothing reaches the relay. Then the denied path (getUserMedia rejects)
// shows the settings hint, the invite scanner turns the safety code away and
// keeps looking, and the bare web page keeps the scanner off. Last, a second
// Chromium whose camera shows Ana's invite starts from the first screen, scans
// it from "I have an invite" and lands on the join request.
//
// Run from the repo root:  node test/e2e_qrscan.mjs
// Ports: 8935 (http), 9336 and 9337 (devtools). Everything started here is killed.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

import { qrMatrix } from "../app/js/qr.js";
import { generateIdentity } from "../app/js/crypto.js";
import { safetyQrText } from "../app/js/roster.js";
import { b64uEncode, safetyNumber } from "../app/js/wire.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HTTP_PORT = 8935;
const CDP_PORT = 9336;
const CDP_PORT_2 = 9337;
const BASE = `http://127.0.0.1:${HTTP_PORT}`;

const fails = [];
function check(name, cond, detail = "") {
  if (cond) console.log(`  ok   ${name}`);
  else {
    console.log(`  FAIL ${name} ${detail}`);
    fails.push(name);
  }
}

// What the Android WebView plants, plus a getUserMedia wrapper that keeps
// every stream handed out so the harness can see the tracks end.
const BRIDGE_STUB = `window.StarlingNative = {
  platform: () => "android",
  version: () => "e2e",
  torSupported: () => false,
  bioSupported: () => false,
  startLocation: () => {},
  stopLocation: () => {},
  hasCameraPermission: () => false,
  requestCamera: (token) => {
    window.__cameraAsked = (window.__cameraAsked || 0) + 1;
    setTimeout(() => window.__starlingCamera(token, !window.__denyCamera), 50);
  },
  openAppSettings: () => { window.__settingsOpened = true; },
};`;
const STREAM_SPY = `(() => {
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  window.__streams = [];
  window.__gumCalls = [];
  navigator.mediaDevices.getUserMedia = async (c) => {
    window.__gumCalls.push(c);
    const s = await real(c);
    window.__streams.push(s);
    return s;
  };
})();`;

// A 640x480 grayscale frame holding the code at six pixels a module, as a
// Y4M the fake capture device plays on a loop.
function y4mOf(text, file) {
  const m = qrMatrix(text);
  const W = 640;
  const H = 480;
  const scale = 6;
  const y = new Uint8Array(W * H).fill(235);
  const size = m.length * scale;
  const ox = (W - size) >> 1;
  const oy = (H - size) >> 1;
  for (let r = 0; r < m.length; r++) {
    for (let c = 0; c < m.length; c++) {
      if (!m[r][c]) continue;
      for (let yy = 0; yy < scale; yy++) y.fill(20, (oy + r * scale + yy) * W + ox + c * scale, (oy + r * scale + yy) * W + ox + (c + 1) * scale);
    }
  }
  const uv = new Uint8Array((W / 2) * (H / 2)).fill(128);
  const parts = [Buffer.from(`YUV4MPEG2 W${W} H${H} F15:1 Ip A1:1 C420jpeg\n`)];
  for (let i = 0; i < 15; i++) parts.push(Buffer.from("FRAME\n"), Buffer.from(y), Buffer.from(uv), Buffer.from(uv));
  writeFileSync(file, Buffer.concat(parts));
  return { modules: m.length, size };
}

async function waitFor(fn, desc, timeout = 20000) {
  const t0 = Date.now();
  let last;
  while (Date.now() - t0 < timeout) {
    last = await fn();
    if (last) return last;
    await sleep(250);
  }
  throw new Error(`timeout waiting for ${desc}; last: ${JSON.stringify(last)}`);
}

function connect(wsUrl) {
  const ws = new WebSocket(wsUrl);
  const pending = new Map();
  const events = [];
  let id = 0;
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    } else if (msg.method) events.push(msg);
  };
  const send = (method, params = {}) =>
    new Promise((resolve) => {
      const myId = ++id;
      pending.set(myId, resolve);
      ws.send(JSON.stringify({ id: myId, method, params }));
    });
  const evalJs = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (r.result?.exceptionDetails) {
      throw new Error(`page threw: ${JSON.stringify(r.result.exceptionDetails.exception?.description)}`);
    }
    return r.result?.result?.value;
  };
  return {
    send,
    evalJs,
    events,
    open: new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = reject;
    }),
    close: () => ws.close(),
  };
}

async function newTab(port = CDP_PORT) {
  const res = await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" });
  const tab = await res.json();
  const c = connect(tab.webSocketDebuggerUrl);
  await c.open;
  await c.send("Page.enable");
  await c.send("Runtime.enable");
  await c.send("Log.enable");
  return c;
}

const click = (c, sel) => c.evalJs(`(() => { const e = document.querySelector('${sel}'); if (!e) return false; e.click(); return true; })()`);
const shown = (c, sel) => c.evalJs(`(() => { const e = document.querySelector('${sel}'); return !!e && !e.hidden && e.offsetParent !== null; })()`);
const text = (c, sel) => c.evalJs(`document.querySelector('${sel}')?.textContent ?? null`);

function cspComplaints(c) {
  return c.events
    .filter((e) => e.method === "Log.entryAdded" || e.method === "Runtime.consoleAPICalled")
    .map((e) => e.params.entry?.text || (e.params.args || []).map((a) => a.value).join(" "))
    .filter((t) => /Content Security Policy|media-src|mediastream/i.test(t || ""));
}

async function boot(c, { wrapper }) {
  if (wrapper) await c.send("Page.addScriptToEvaluateOnNewDocument", { source: BRIDGE_STUB });
  await c.send("Page.addScriptToEvaluateOnNewDocument", { source: STREAM_SPY });
  await c.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  await c.send("Page.navigate", { url: BASE + "/" });
  await waitFor(() => c.evalJs("!!window.__starlingApi && !!window.__starlingInternals"), "app booted");
}

async function createCircle(c) {
  await waitFor(() => c.evalJs("!document.getElementById('screen-onboarding').hidden"), "onboarding on screen");
  await click(c, '[data-testid="onboarding-create"]');
  await waitFor(() => shown(c, '[data-testid="identity-name"]'), "identity form");
  await c.evalJs(`(() => {
    for (const [sel, v] of [['[data-testid="identity-name"]', "Ana"], ['[data-testid="circle-name"]', "Trip"]]) {
      const e = document.querySelector(sel); e.value = v; e.dispatchEvent(new Event("input", { bubbles: true }));
    }
  })()`);
  await waitFor(() => c.evalJs(`!document.querySelector('[data-testid="identity-save"]').disabled`), "save enabled");
  await click(c, '[data-testid="identity-save"]');
  await waitFor(() => c.evalJs(`!!document.querySelector('[data-testid="invite-link"]')?.textContent.includes('#j=')`), "invite sheet", 30000);
  const link = await text(c, '[data-testid="invite-link"]');
  // Whatever is stacked on top of the map after the save goes, top first.
  await waitFor(async () => {
    const open = await c.evalJs("[...document.querySelectorAll('.ov-wrap')].map((w) => w.querySelector('.ov-panel')?.dataset.testid)");
    if (!open.length) return true;
    await click(c, ".ov-wrap:last-of-type .ov-close");
    await sleep(400);
    return false;
  }, "sheets after the save closed");
  return link;
}

function startChromium(port, profile, y4m) {
  return spawn(
    "chromium",
    [
      "--headless=new",
      `--remote-debugging-port=${port}`,
      "--user-data-dir=" + profile,
      "--no-sandbox",
      "--disable-gpu",
      "--use-fake-device-for-media-stream",
      "--use-fake-ui-for-media-stream",
      `--use-file-for-fake-video-capture=${y4m}`,
      "about:blank",
    ],
    { stdio: "ignore" },
  );
}

async function main() {
  const work = mkdtempSync(path.join(tmpdir(), "starling-qrscan-e2e-"));
  const profile = path.join(work, "profile");
  const y4m = path.join(work, "camera.y4m");

  // The member whose code the camera will show.
  const bo = await generateIdentity();
  const boNumber = await safetyNumber(bo.pk, bo.epk);
  const payload = safetyQrText(bo.memberId, boNumber);
  const drawn = y4mOf(payload, y4m);
  console.log(`camera frame: version ${(drawn.modules - 17) / 4} code, ${drawn.size}px of 640x480`);

  const server = spawn("node", [path.join(ROOT, "test", "serve_local.mjs"), String(HTTP_PORT)], {
    cwd: ROOT,
    env: { ...process.env, STARLING_TEST: "1", STARLING_WRAPPER_HEADERS: "1", RATE_POST_MIN: "100000", RATE_GET_MIN: "100000" },
    stdio: "ignore",
  });
  const chromium = startChromium(CDP_PORT, profile, y4m);
  let chromium2 = null;
  try {
    await waitFor(async () => {
      try {
        const [a, b] = await Promise.all([
          fetch(`${BASE}/api/v2/health`).then((r) => r.ok).catch(() => false),
          fetch(`http://127.0.0.1:${CDP_PORT}/json/version`).then((r) => r.ok).catch(() => false),
        ]);
        return a && b;
      } catch {
        return false;
      }
    }, "server and devtools up");

    // ------------------------------------------------------- in the app
    const app = await newTab();
    await boot(app, { wrapper: true });
    const inviteLink = await createCircle(app);
    check("Ana's invite link was on the invite sheet", /#j=/.test(inviteLink || ""), inviteLink);
    const pinnedBo = await app.evalJs(`window.__starlingInternals.addPinned(${JSON.stringify({
      memberId: bo.memberId,
      alg: bo.alg,
      pk: b64uEncode(bo.pk),
      epk: b64uEncode(bo.epk),
      name: "Bo",
    })}).then((e) => !!e)`);
    check("Bo pinned into Ana's roster", pinnedBo === true);

    await click(app, '[data-testid="members-open"]');
    await waitFor(() => app.evalJs(`/\\d{5}/.test(document.querySelector('[data-testid="own-safety"]')?.textContent || "")`), "own safety number");
    check("Scan theirs is offered in the app", await shown(app, '[data-testid="safety-scan"]'));
    check("the web-only note is hidden in the app", !(await shown(app, '[data-testid="safety-scan-note"]')));
    const boRow = `[data-testid="member-row"][data-member="${bo.memberId}"]`;
    check("Bo's row starts out not verified", (await text(app, `${boRow} .verify-pill`)) === "Not verified");

    await click(app, '[data-testid="safety-show-qr"]');
    await waitFor(() => app.evalJs(`!!document.querySelector('[data-testid="safety-qr-card"] svg')`), "own code drawn");
    const ownLabel = await app.evalJs(`document.querySelector('[data-testid="safety-qr-card"] svg').getAttribute("aria-label")`);
    check("own code is labelled for a screen reader", ownLabel === "Safety number QR code", ownLabel);
    await click(app, '[data-testid="safety-qr"] .ov-close');
    await waitFor(() => app.evalJs(`!document.querySelector('[data-testid="safety-qr"]')`), "own code closed");

    await click(app, '[data-testid="safety-scan"]');
    await waitFor(() => shown(app, '[data-testid="scan-sheet"]'), "scan sheet");
    const streamed = await waitFor(
      () => app.evalJs(`(() => { const v = document.querySelector('[data-testid="scan-sheet"] video'); return !!v && !!v.srcObject && v.readyState >= 2 && v.videoWidth > 0; })()`),
      "camera stream playing in the sheet",
      15000,
    ).catch(() => false);
    check("the video element plays the camera stream", streamed === true);
    if (streamed !== true) {
      const why = await app.evalJs(`(() => {
        const v = document.querySelector('[data-testid="scan-sheet"] video');
        const s = window.__streams[0];
        return {
          status: document.querySelector('[data-testid="scan-status"]')?.textContent,
          streams: window.__streams.length,
          tracks: s ? s.getTracks().map((t) => t.kind + ":" + t.readyState + ":" + t.label) : null,
          video: v ? { src: !!v.srcObject, ready: v.readyState, w: v.videoWidth, paused: v.paused, err: v.error && v.error.message } : null,
          errors: window.__starlingErrors || [],
        };
      })()`);
      console.log("       why:", JSON.stringify(why), "csp:", JSON.stringify(cspComplaints(app)));
    }
    check("the bridge was asked for the camera permission first", (await app.evalJs("window.__cameraAsked")) === 1);
    check("the page asked for the rear camera and no audio", await app.evalJs(`(() => { const c = window.__gumCalls[0]; return c && c.audio === false && c.video && c.video.facingMode === "environment"; })()`));

    await waitFor(() => shown(app, '[data-testid="scan-result"]'), "scan verdict", 20000);
    const verdict = await text(app, '[data-testid="scan-result"] .ov-body');
    check("the verdict says the code matches Bo", /matches the keys this phone holds for Bo/.test(verdict || ""), verdict);
    check("the verdict shows Bo's number", (await text(app, '[data-testid="scan-number"]'))?.replace(/\s+/g, " ").trim() === boNumber);
    const sheetGone = await waitFor(() => app.evalJs(`!document.querySelector('[data-testid="scan-sheet"]')`), "scan sheet gone", 5000).catch(() => false);
    check("the scan sheet is gone once the code read", sheetGone === true);
    check("every camera track is ended after the read", await app.evalJs(`window.__streams.length === 1 && window.__streams[0].getTracks().every((t) => t.readyState === "ended")`));
    check("the page CSP let the stream play as it stands", cspComplaints(app).length === 0, cspComplaints(app).join(" | "));

    check("Bo's row is still not verified before the tap", (await text(app, `${boRow} .verify-pill`)) === "Not verified");
    await click(app, '[data-testid="scan-mark-verified"]');
    await waitFor(() => app.evalJs(`document.querySelector('${boRow} .verify-pill')?.textContent === "Verified"`), "Bo marked verified");
    check("the mark lands on Bo's row", (await text(app, `${boRow} .verify-pill`)) === "Verified");
    const verdictGone = await waitFor(() => app.evalJs(`!document.querySelector('[data-testid="scan-result"]')`), "verdict gone", 5000).catch(() => false);
    check("the verdict closed after marking", verdictGone === true);
    check("no page errors", ((await app.evalJs("window.__starlingErrors || []")) || []).length === 0, JSON.stringify(await app.evalJs("window.__starlingErrors || []")));

    // ------------------------------------------------- camera turned down
    await app.evalJs("window.__denyCamera = true");
    await click(app, '[data-testid="safety-scan"]');
    await waitFor(() => app.evalJs(`/turned down/.test(document.querySelector('[data-testid="scan-status"]')?.textContent || "")`), "denied message");
    check("a denied camera says so and offers settings", await app.evalJs(`(() => { const b = [...document.querySelectorAll('[data-testid="scan-sheet"] button')].find((x) => x.textContent === "Open app settings"); return !!b && !b.hidden; })()`));
    await app.evalJs(`[...document.querySelectorAll('[data-testid="scan-sheet"] button')].find((x) => x.textContent === "Open app settings").click()`);
    check("the settings button reaches the bridge", (await app.evalJs("window.__settingsOpened === true")));
    await click(app, '[data-testid="scan-sheet"] .ov-close');
    await waitFor(() => app.evalJs(`!document.querySelector('[data-testid="scan-sheet"]')`), "scan sheet closed");
    check("no stream was asked for on the denied path", await app.evalJs("window.__streams.length === 1 && window.__gumCalls.length === 1 && window.__cameraAsked === 2"));

    // ------------------------------------- the invite scanner, wrong code
    await app.evalJs("window.__denyCamera = false");
    await click(app, '[data-testid="circle-open"]');
    await waitFor(() => shown(app, '[data-testid="circle-join"]'), "circle sheet");
    await click(app, '[data-testid="circle-join"]');
    await waitFor(() => shown(app, '[data-testid="paste-scan"]'), "Scan a code on the paste sheet");
    check("the paste sheet offers Scan a code in the app", await shown(app, '[data-testid="paste-scan"]'));
    await click(app, '[data-testid="paste-scan"]');
    await waitFor(() => shown(app, '[data-testid="scan-sheet"]'), "invite scan sheet");
    check("the invite scanner says what it is for", (await text(app, '[data-testid="scan-sheet"] .ov-title')) === "Scan an invite code");
    const turnedAway = await waitFor(
      () => app.evalJs(`document.querySelector('[data-testid="scan-status"]')?.textContent === "That is a safety number code, not an invite."`),
      "the safety code turned away",
      20000,
    ).catch(() => false);
    check("a safety number code is named, not joined", turnedAway === true, await text(app, '[data-testid="scan-status"]'));
    await sleep(1000);
    check("the camera keeps looking after a wrong code", await app.evalJs(`(() => { const v = document.querySelector('[data-testid="scan-sheet"] video'); return !!v && !!v.srcObject && window.__streams.at(-1).getTracks().every((t) => t.readyState === "live"); })()`));
    check("no join sheet opened for it", !(await shown(app, '[data-testid="join-sheet"]')));
    await click(app, '[data-testid="scan-sheet"] .ov-close');
    await waitFor(() => app.evalJs(`!document.querySelector('[data-testid="scan-sheet"]')`), "invite scan sheet closed");
    check("closing it ends the camera", await app.evalJs(`window.__streams.at(-1).getTracks().every((t) => t.readyState === "ended")`));

    const relayGets = await fetch(`${BASE}/debug/dump`).then((r) => r.text()).catch(() => "");
    check("nothing about the scan reached the relay", !relayGets.includes("starling:sn:") && !relayGets.includes(boNumber.replace(/ /g, "")));
    app.close();

    // ----------------------------------------------------- bare web page
    const web = await newTab();
    await boot(web, { wrapper: false });
    await waitFor(() => shown(web, '[data-testid="members-open"]'), "the circle reopened on the web tab", 30000);
    await click(web, '[data-testid="members-open"]');
    await waitFor(() => shown(web, '[data-testid="safety-show-qr"]'), "members sheet on the web");
    check("the web page still shows the code", await shown(web, '[data-testid="safety-show-qr"]'));
    check("the web page hides the scanner", !(await shown(web, '[data-testid="safety-scan"]')));
    check("the web page says scanning lives in the app", await shown(web, '[data-testid="safety-scan-note"]'));
    await web.evalJs(`document.querySelectorAll('.ov-close').forEach((b) => b.click())`);
    await click(web, '[data-testid="circle-open"]');
    await waitFor(() => shown(web, '[data-testid="circle-join"]'), "circle sheet on the web");
    await click(web, '[data-testid="circle-join"]');
    await waitFor(() => shown(web, '[data-testid="paste-sheet"]'), "paste sheet on the web");
    check("the web paste sheet has no Scan a code", !(await shown(web, '[data-testid="paste-scan"]')));
    web.close();

    // -------------------------------- a fresh phone scans Ana's invite
    const y4mInvite = path.join(work, "invite.y4m");
    const drawnInvite = y4mOf(inviteLink, y4mInvite);
    console.log(`invite frame: version ${(drawnInvite.modules - 17) / 4} code, ${drawnInvite.size}px of 640x480`);
    chromium2 = startChromium(CDP_PORT_2, path.join(work, "profile2"), y4mInvite);
    await waitFor(() => fetch(`http://127.0.0.1:${CDP_PORT_2}/json/version`).then((r) => r.ok).catch(() => false), "second devtools up");
    const joiner = await newTab(CDP_PORT_2);
    await boot(joiner, { wrapper: true });
    await waitFor(() => shown(joiner, '[data-testid="onboarding-join"]'), "I have an invite on the first screen");
    await click(joiner, '[data-testid="onboarding-join"]');
    await waitFor(() => shown(joiner, '[data-testid="paste-scan"]'), "Scan a code under I have an invite");
    await click(joiner, '[data-testid="paste-scan"]');
    await waitFor(() => shown(joiner, '[data-testid="scan-sheet"]'), "invite scan sheet on the fresh phone");
    const joinShown = await waitFor(() => shown(joiner, '[data-testid="join-sheet"]'), "join request sheet", 20000).catch(() => false);
    check("scanning the invite lands on the join request", joinShown === true, await text(joiner, '[data-testid="scan-status"]'));
    const scanGone = await waitFor(() => joiner.evalJs(`!document.querySelector('[data-testid="scan-sheet"]')`), "scan sheet gone", 5000).catch(() => false);
    check("the scan sheet is gone once the invite read", scanGone === true);
    check("the camera ended once the invite read", await joiner.evalJs(`window.__streams.length === 1 && window.__streams[0].getTracks().every((t) => t.readyState === "ended")`));
    check("the join sheet is the request for this circle", /You have an invite to a circle/.test((await text(joiner, '[data-testid="join-sheet"]')) || ""));
    check("no page errors on the fresh phone", ((await joiner.evalJs("window.__starlingErrors || []")) || []).length === 0, JSON.stringify(await joiner.evalJs("window.__starlingErrors || []")));
    joiner.close();
  } finally {
    chromium.kill();
    chromium2?.kill();
    server.kill();
    rmSync(work, { recursive: true, force: true });
  }

  if (fails.length) {
    console.log(`\n${fails.length} check(s) failed`);
    process.exit(1);
  }
  console.log("\nall checks passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
