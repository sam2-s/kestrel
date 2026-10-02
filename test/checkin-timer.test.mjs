// The check-in timer against the real main.js and net.js.
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

const { internals } = await loadApp(harness);
const state = internals.state;
const { openGeneration } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed, openMessage, sealMessage, buildPost } = await import("../app/js/crypto.js");
const { b64uDecode, b64uEncode } = await import("../app/js/wire.js");
const { dbGet, dbSet, wipeAll } = await import("../app/js/store.js");
const { createRoster, displayStatus, sortMembers } = await import("../app/js/net.js");
const { overdue, DUE_GRACE_MS } = await import("../app/js/checkin.js");
const { GEN_SLOT, packGenMeta, writeRecordAtRest } = await import("../app/js/circles.js");

test.after(async () => {
  if (state.sharing) await internals.setSharing(false);
  delete globalThis.StarlingNative;
  harness.stopTimers();
});

const NATIVE = {
  startLocation: () => {},
  stopLocation: () => {},
  setShareCadence: () => {},
  clearStopRecord: () => {},
  keepSharing: () => false,
  setKeepSharing: () => {},
  windowShown: () => true,
  pulse: () => {},
};

async function inCircle() {
  if (state.sharing) await internals.setSharing(false);
  globalThis.StarlingNative = { ...NATIVE };
  internals.resetShareResumeGuard();
  state.demo = false;
  state.locked = false;
  state.stopRecord = null;
  state.sosActive = false;
  state.circleShare = { precision: null, cadence: null };
  state.identity = state.identity || (await generateIdentity());
  if (!state.gen) {
    state.gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(Date.now()) });
    state.gen.at = Date.now();
    state.genRoster = new Set();
    state.pinned = new Map();
  }
  internals.setupNet();
}

async function sharing() {
  await inCircle();
  await internals.setSharing(true);
  state.me = { lat: 40.785, lon: -73.968, acc: 5, ts: Date.now() };
  assert.equal(state.sharing, true);
}

async function openOwnPost(body) {
  const p = JSON.parse(body);
  const key = await state.gen.ratchet.keyFor(p.e, state.identity.memberId, p.ts);
  return openMessage(key, state.gen.channelId, state.identity.memberId, p.e, p.ts, b64uDecode(p.n), b64uDecode(p.c));
}

function capturePosts() {
  const posts = [];
  harness.onFetch(async (url, init) => {
    if (url.includes(`/f/${state.gen.channelId}/loc`)) posts.push(init.body);
    return undefined;
  });
  return posts;
}

// One member's post, sealed and signed the way their phone would.
async function memberEntry(gen, who, fields, ts) {
  const e = epochAt(ts);
  const key = await gen.ratchet.keyFor(e, who.memberId, ts);
  const sealed = await sealMessage(key, gen.channelId, who.memberId, e, ts, { v: 2, ts, ...fields });
  const post = await buildPost(who, gen.channelId, e, sealed, ts);
  return {
    m: who.memberId,
    alg: who.alg,
    pk: b64uEncode(who.pk),
    epk: b64uEncode(who.epk),
    points: [{ e: post.e, ts: post.ts, srv: post.ts, n: post.n, c: post.c, sig: post.sig }],
  };
}

test("a post carries due while a timer runs and loses it after a check-in", async () => {
  await sharing();
  const posts = capturePosts();
  try {
    const before = Date.now();
    assert.equal(await internals.startCheckinTimer(60), true);
    await settle();
    const due = internals.checkinDue();
    assert.ok(due >= before + 60 * 60 * 1000 && due <= Date.now() + 60 * 60 * 1000);
    const armed = await openOwnPost(posts.at(-1));
    assert.equal(armed.t, "loc", "arming while sharing posts at once");
    assert.equal(armed.due, due);
    assert.deepEqual(await dbGet("checkinDue"), { due, member: state.identity.memberId });

    await internals.sendLoc(true);
    await settle();
    assert.equal((await openOwnPost(posts.at(-1))).due, due, "every later post carries it too");

    await internals.doCheckin();
    await settle();
    const checkin = await openOwnPost(posts.at(-1));
    assert.equal(checkin.t, "checkin");
    assert.equal(checkin.due, undefined, "the check-in itself is what clears it on every phone");
    assert.equal(internals.checkinDue(), null);
    assert.equal(await dbGet("checkinDue"), undefined);
  } finally {
    harness.onFetch(null);
  }
});

test("stopping sharing keeps the timer: the bye still carries due", async () => {
  await sharing();
  const posts = capturePosts();
  try {
    await internals.startCheckinTimer(30);
    await settle();
    const due = internals.checkinDue();
    assert.ok(due);
    await (await internals.setSharing(false));
    await settle();
    const bye = await openOwnPost(posts.at(-1));
    assert.equal(bye.t, "bye");
    assert.equal(bye.due, due, "the circle still holds the deadline after this phone goes quiet");
    assert.equal(internals.checkinDue(), due);
    assert.deepEqual(await dbGet("checkinDue"), { due, member: state.identity.memberId });

    // Armed with sharing off: one check-in carrying the deadline, and sharing stays off.
    await internals.startCheckinTimer(120);
    await settle();
    const armed = await openOwnPost(posts.at(-1));
    assert.equal(armed.t, "checkin");
    assert.equal(armed.due, internals.checkinDue());
    assert.equal(state.sharing, false, "a timer never starts sharing by itself");
  } finally {
    harness.onFetch(null);
    await internals.doCheckin();
  }
});

test("the roster keeps due from the last message and drops one more than 24h from its ts", async () => {
  const t0 = Date.now() - 60_000;
  const gen = await openGeneration({ seed: new Uint8Array(newSeed()), g: 0, e0: epochAt(t0) });
  const roster = createRoster({ channelId: gen.channelId, ratchet: gen.ratchet, selfId: "f".repeat(32), pinned: new Map() });
  const who = await generateIdentity();
  const day = 24 * 60 * 60 * 1000;
  const feed = async (fields, ts) => {
    await roster.ingest([await memberEntry(gen, who, fields, ts)], Date.now());
    return roster.get(who.memberId).due;
  };

  assert.equal(await feed({ t: "loc", due: t0 + 30 * 60_000 }, t0), t0 + 30 * 60_000);
  assert.equal(await feed({ t: "bye", due: t0 + 30 * 60_000 }, t0 + 1), t0 + 30 * 60_000, "a bye keeps it");
  assert.equal(await feed({ t: "loc" }, t0 + 2), null, "a message without due clears it");
  assert.equal(await feed({ t: "loc", due: t0 + 3 }, t0 + 3), t0 + 3, "due equal to ts is a deadline");
  assert.equal(await feed({ t: "loc", due: t0 + 4 + day }, t0 + 4), t0 + 4 + day, "exactly a day ahead is allowed");
  assert.equal(await feed({ t: "loc", due: t0 + 5 + day + 1 }, t0 + 5), null, "past a day ahead is junk");
  assert.equal(await feed({ t: "loc", due: "soon" }, t0 + 6), null);
  assert.equal(await feed({ t: "loc", due: t0 - 1000 }, t0 + 7), t0 - 1000, "a passed deadline stays");
  assert.equal(await feed({ t: "loc", due: t0 + 8 - day }, t0 + 8), t0 + 8 - day, "exactly a day behind is allowed");
  assert.equal(await feed({ t: "loc", due: t0 + 9 - day - 1 }, t0 + 9), null, "past a day behind is junk");
});

test("a member is overdue only after due plus the grace", () => {
  const due = 1_800_000_000_000;
  assert.equal(overdue({ due }, due), false);
  assert.equal(overdue({ due }, due + DUE_GRACE_MS - 1), false);
  assert.equal(overdue({ due }, due + DUE_GRACE_MS), true);
  assert.equal(overdue({ due: null }, due + DUE_GRACE_MS * 10), false);
  assert.equal(overdue({}, due), false);

  const now = due + DUE_GRACE_MS;
  const live = { id: "a", type: "loc", ts: now - 1000 };
  const late = { id: "b", type: "loc", ts: now - 2000, due };
  const sos = { id: "c", type: "sos", ts: now - 3000 };
  assert.equal(displayStatus(late, now), "overdue");
  assert.equal(displayStatus(late, now - 1), "live", "one millisecond before the grace runs out it is still live");
  assert.deepEqual(sortMembers([live, late, sos], now).map((r) => r.id), ["c", "b", "a"], "right after an SOS");
});

test("an overdue member fires one urgent notification and one card, and a check-in clears both", async () => {
  await inCircle();
  const calls = [];
  globalThis.StarlingNative = {
    ...NATIVE,
    windowShown: () => false,
    notify: (...a) => calls.push(["notify", ...a]),
    cancelNotify: (tag) => calls.push(["cancel", tag]),
  };
  const who = await generateIdentity();
  const tag = `due-${who.memberId}`;
  const t0 = Date.now();
  const due = t0 + 30 * 60_000;
  const realNow = Date.now;
  const at = (ms) => (Date.now = () => ms);
  try {
    await internals.roster().ingest([await memberEntry(state.gen, who, { t: "loc", name: "Juno", lat: 1, lon: 2, due }, t0)], t0);
    const card = () => internals.alertItems().filter((i) => i.id === `due:${who.memberId}`);

    at(due + DUE_GRACE_MS - 1);
    internals.checkAlerts();
    assert.deepEqual(calls.filter((c) => c[0] === "notify"), [], "not before the grace runs out");
    assert.equal(card().length, 0);

    at(due + DUE_GRACE_MS);
    internals.checkAlerts();
    internals.checkAlerts();
    const told = calls.filter((c) => c[0] === "notify" && c[3] === tag);
    assert.equal(told.length, 1, "one notification per missed deadline, not one per poll");
    assert.equal(told[0][4], true, "on the urgent path");
    assert.equal(card().length, 1);
    assert.equal(card()[0].kind, "sos");
    assert.match(card()[0].title, /Juno missed their check-in/);
    assert.equal(card()[0].actions[0].label, "Show on map");
    Date.now = realNow;

    await internals.roster().ingest([await memberEntry(state.gen, who, { t: "checkin", name: "Juno" }, t0 + 1000)], t0 + 1000);
    at(due + DUE_GRACE_MS + 5000);
    internals.checkAlerts();
    assert.ok(calls.some((c) => c[0] === "cancel" && c[1] === tag), "the check-in takes the notification back down");
    assert.equal(card().length, 0, "and the card goes with it");
  } finally {
    Date.now = realNow;
    globalThis.StarlingNative = { ...NATIVE };
  }
});

test("a phone still posting after its deadline is overdue on every receiver until it checks in", async () => {
  await sharing();
  const posts = capturePosts();
  const realNow = Date.now;
  try {
    await internals.startCheckinTimer(1);
    await settle();
    const own = internals.checkinDue();
    Date.now = () => own + 15_000;
    await internals.sendLoc(true);
    await settle();
    Date.now = realNow;
    const late = await openOwnPost(posts.at(-1));
    assert.ok(late.ts > own, "this post went out after the deadline");
    assert.equal(late.due, own, "and still carries it");
  } finally {
    Date.now = realNow;
    harness.onFetch(null);
    await internals.doCheckin();
    await settle();
    if (state.sharing) await internals.setSharing(false);
  }

  const calls = [];
  globalThis.StarlingNative = {
    ...NATIVE,
    windowShown: () => false,
    notify: (...a) => calls.push(["notify", ...a]),
    cancelNotify: (tag) => calls.push(["cancel", tag]),
  };
  const who = await generateIdentity();
  const tag = `due-${who.memberId}`;
  const card = () => internals.alertItems().filter((i) => i.id === `due:${who.memberId}`);
  const t0 = Date.now();
  const due = t0 + 60_000;
  const post = async (fields, ts) => {
    await internals.roster().ingest([await memberEntry(state.gen, who, { name: "Juno", lat: 1, lon: 2, ...fields }, ts)], ts);
    Date.now = () => ts;
    internals.checkAlerts();
  };
  try {
    let ts = t0;
    for (; ts <= due + DUE_GRACE_MS + 45_000; ts += 15_000) await post({ t: "loc", due }, ts);
    await post({ t: "bye", due }, ts);
    assert.equal(internals.roster().get(who.memberId).due, due, "the receiver keeps a deadline the posts went past");
    assert.equal(displayStatus(internals.roster().get(who.memberId), ts), "overdue");
    assert.equal(calls.filter((c) => c[0] === "notify" && c[3] === tag).length, 1, "told once, while the posts kept coming");
    assert.equal(calls.some((c) => c[0] === "cancel" && c[1] === tag), false, "and no later post took it back");
    assert.equal(card().length, 1);

    await post({ t: "checkin" }, ts + 15_000);
    assert.ok(calls.some((c) => c[0] === "cancel" && c[1] === tag), "the check-in takes it down");
    assert.equal(card().length, 0);
  } finally {
    Date.now = realNow;
    globalThis.StarlingNative = { ...NATIVE };
  }
});

test("an armed timer survives a reload and an expired one says so on boot", async () => {
  await wipeAll();
  if (state.sharing) await internals.setSharing(false);
  const identity = await generateIdentity();
  const e0 = epochAt(Date.now());
  const gen = await openGeneration({ seed: newSeed(), g: 0, e0 });
  const snap = gen.ratchet.snapshot();
  const kvFace = { get: dbGet, set: dbSet, del: async () => {} };
  await dbSet("identity", identity);
  await dbSet("secret", snap.ck0);
  await dbSet("circleName", "Field team");
  await writeRecordAtRest(kvFace, null, GEN_SLOT, packGenMeta({ ...gen, ckEpoch: snap.e0, genRoster: [] }));

  const coldBoot = async () => {
    internals.teardownNet();
    state.gen = null;
    state.identity = null;
    state.locked = false;
    state.lock = null;
    state.screen = "onboarding";
    await internals.boot();
    await settle();
  };

  const due = Date.now() + 2 * 60 * 60 * 1000;
  await dbSet("checkinDue", { due, member: identity.memberId });
  await coldBoot();
  assert.equal(state.identity?.memberId, identity.memberId, "the stored circle came back");
  assert.equal(internals.checkinDue(), due, "and so did its timer");
  assert.equal(internals.alertItems().some((i) => i.id === "own-due"), false);

  const past = Date.now() - 10 * 60 * 1000;
  await dbSet("checkinDue", { due: past, member: identity.memberId });
  await coldBoot();
  assert.equal(internals.checkinDue(), past);
  const card = internals.alertItems().find((i) => i.id === "own-due");
  assert.ok(card, "a timer that ran out while the app was closed says so");
  assert.match(card.title, /You missed your check-in/);
  assert.equal(card.actions[0].label, "Check in now");

  await dbSet("checkinDue", { due, member: "0".repeat(32) });
  await coldBoot();
  assert.equal(internals.checkinDue(), null, "another circle's timer is not this one's");
});
