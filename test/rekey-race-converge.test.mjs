// Two members who re-key the same generation in the same minute used to split
// the circle in half, silently.
//
// Each rotator opens its own g+1 on its own channel, and moving tears down the
// poller on the channel it left, so neither ever saw the other's wraps and
// everyone else followed whichever wrap they read first. Nothing surfaced it:
// the rotators clear rosterPending themselves, and a follower's roster hash
// agrees with the rotator it followed.
//
// The fix keeps the generation just left readable for a grace window on its old
// channel, judges a competing re-key by lowest member id, and has the loser
// rewind to the generation both rotators worked from and adopt the winner. These
// two checks are the device-level halves of that: a follower that backed the
// loser, and a rotator whose own re-key lost.
//
// The window is deliberately never opened over a membership change; that rule
// has its own checks in rekey-race-removal.test.mjs.
import test from "node:test";
import assert from "node:assert/strict";

import { installDom, loadApp, settle } from "./dom-harness.mjs";

const harness = installDom();
const { internals, api } = await loadApp(harness);
const state = internals.state;

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

const { openGeneration, buildRekey } = await import("../app/js/rekey.js");
const { epochAt } = await import("../app/js/ratchet.js");
const { generateIdentity, newSeed, sealMessage, buildPost } = await import("../app/js/crypto.js");
const { b64uEncode } = await import("../app/js/wire.js");
const { dbSet, wipeAll } = await import("../app/js/store.js");

test.after(() => harness.stopTimers());

// One normal poll of the old channel (net.js POLL_MS) plus room to act on what
// it finds.
const CONVERGE_MS = 12_000;

const ok = (obj) => ({ ok: true, status: 200, json: async () => obj });
const rec = (id) => ({ memberId: id.memberId, epk: id.epk });
const channelOf = async (built) =>
  (await openGeneration({ seed: new Uint8Array(built.seed), g: built.g, e0: built.e0 })).channelId;

async function waitFor(cond, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await settle(50);
  }
  return cond();
}

// Sorted so a check can say which id wins the tie-break before it runs.
async function sortedIdentities(n) {
  const ids = [];
  for (let i = 0; i < n; i++) ids.push(await generateIdentity());
  return ids.sort((a, b) => (a.memberId < b.memberId ? -1 : 1));
}

// This device as `self`, in generation 0 with `peers` pinned and in the
// founding roster. Each peer gets its own copy of the same generation, which is
// what makes two rotations from one parent possible.
async function circleWith(self, peers) {
  await wipeAll();
  state.circles = [];
  state.chainWiped = null;
  state.locked = false;
  state.lock = null;
  state.vaultKey = null;
  state.demo = false;
  state.chainDestroyed = false;
  state.sharing = false;
  state.pinned = new Map();
  state.keyChanges.clear();
  state.rosterPending = null;
  state.invite = null;
  state.joining = null;
  state.joinRequests = [];
  state.missedRekey = false;
  state.identity = self;
  await dbSet("identity", self);
  const seed = newSeed();
  const e0 = epochAt(Date.now());
  state.gen = await openGeneration({ seed: new Uint8Array(seed), g: 0, e0 });
  state.gen.at = Date.now();
  const gens = [];
  for (const p of peers) {
    assert.ok(
      await internals.addPinned({
        alg: p.alg,
        pk: b64uEncode(p.pk),
        epk: b64uEncode(p.epk),
        name: "Peer",
      }),
    );
    gens.push(await openGeneration({ seed: new Uint8Array(seed), g: 0, e0 }));
  }
  state.genRoster = new Set(state.pinned.keys());
  window.__starlingErrors.length = 0;
  return gens;
}

// A rotator's re-key as the relay serves it back: one entry for the member, one
// point per wrap, sealed and signed on the old channel the way net.js does it.
async function servedRekey(identity, gen, built) {
  const points = [];
  let ts = Date.now();
  for (const fields of built.posts) {
    ts += 1;
    const e = await gen.ratchet.currentEpoch(ts);
    const key = await gen.ratchet.keyFor(e, identity.memberId, ts);
    const sealed = await sealMessage(key, gen.channelId, identity.memberId, e, ts, {
      v: 2,
      ts,
      ...fields,
    });
    const post = await buildPost(identity, gen.channelId, e, sealed, ts);
    points.push({ e: post.e, ts: post.ts, srv: post.ts, n: post.n, c: post.c, sig: post.sig });
  }
  return {
    m: identity.memberId,
    alg: identity.alg,
    pk: b64uEncode(identity.pk),
    epk: b64uEncode(identity.epk),
    points,
  };
}

// A relay that serves whatever `view` says a channel holds on its nth read,
// ordered by member id like the real one, and accepts every post.
function relay(view) {
  const reads = new Map();
  harness.onFetch(async (url, init) => {
    const m = /\/api\/v2\/f\/([0-9a-f]{32})(\/loc)?/.exec(url);
    if (!m) return null;
    const [, chan, loc] = m;
    if (loc || init?.method === "POST") return ok({ ok: true, now: Date.now() });
    const n = (reads.get(chan) || 0) + 1;
    reads.set(chan, n);
    const members = [...(view(chan, n) || [])].sort((a, b) => (a.m < b.m ? -1 : 1));
    return ok({ now: Date.now(), members });
  });
  return reads;
}

test("a follower that backed the losing re-key ends up on the winner's generation", { timeout: 60_000 }, async () => {
  const [win, lose, other] = await sortedIdentities(3);
  const [winGen, loseGen] = await circleWith(other, [win, lose]);
  const oldChannel = state.gen.channelId;

  const now = Date.now();
  const byWin = await buildRekey({ identity: win, gen: winGen, recipients: [rec(other), rec(lose)], now });
  const byLose = await buildRekey({ identity: lose, gen: loseGen, recipients: [rec(other), rec(win)], now });
  const winEntry = await servedRekey(win, winGen, byWin);
  const loseEntry = await servedRekey(lose, loseGen, byLose);
  const winChannel = await channelOf(byWin);
  const loseChannel = await channelOf(byLose);

  // The first read of the old channel lands before the winner's wrap does, so
  // this device follows the loser. Every later read holds both, as the relay
  // would for the rest of the day.
  const reads = relay((chan, n) =>
    chan === oldChannel ? (n === 1 ? [loseEntry] : [winEntry, loseEntry]) : [],
  );
  await internals.enterCircle();

  // Read off the relay rather than off state: by the time a check looks, a
  // fixed device may already have moved on.
  assert.ok(
    await waitFor(() => reads.has(loseChannel), 3000),
    "this device followed the loser first, onto the loser's channel",
  );

  const converged = await waitFor(() => state.gen?.channelId === winChannel, CONVERGE_MS);
  harness.onFetch(null);
  assert.ok(converged, "and then moves to the winner's channel, where the rest of the circle is");
});

test("a rotator whose own re-key loses the race moves to the winner too", { timeout: 60_000 }, async () => {
  const [win, self, other] = await sortedIdentities(3);
  const [winGen] = await circleWith(self, [win, other]);
  const oldChannel = state.gen.channelId;

  const byWin = await buildRekey({
    identity: win,
    gen: winGen,
    recipients: [rec(self), rec(other)],
    now: Date.now(),
  });
  const winEntry = await servedRekey(win, winGen, byWin);
  const winChannel = await channelOf(byWin);

  // The winner's wraps land in the same moment as this device's own, so nothing
  // it read before rotating contained them.
  let landed = false;
  relay((chan) => (chan === oldChannel && landed ? [winEntry] : []));
  await internals.enterCircle();
  await settle();

  assert.equal(await api.rekeyCircle(), true, "this device rotated");
  assert.notEqual(state.gen.channelId, oldChannel, "and left the old channel");
  landed = true;

  const converged = await waitFor(() => state.gen?.channelId === winChannel, CONVERGE_MS);
  harness.onFetch(null);
  assert.ok(converged, "the losing rotator joins the winner instead of sitting alone");
});
