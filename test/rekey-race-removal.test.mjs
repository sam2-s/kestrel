// A removed member must not be able to ride the re-key grace window back in.
//
// The window that reconciles two racing re-keys keeps the old channel readable
// for a few minutes, and a member removed by the re-key that opened it still
// holds that channel's keys and is still in the roster the window remembers.
// So the window is never opened over a membership change. This check is the
// one that would notice if that rule went away: the removed member posts a
// competing re-key with a member id that would win the tie-break, and the
// device must stay where its own removal put it.
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

const ok = (obj) => ({ ok: true, status: 200, json: async () => obj });
const rec = (id) => ({ memberId: id.memberId, epk: id.epk });
const channelOf = async (built) =>
  (await openGeneration({ seed: new Uint8Array(built.seed), g: built.g, e0: built.e0 })).channelId;

async function sortedIdentities(n) {
  const ids = [];
  for (let i = 0; i < n; i++) ids.push(await generateIdentity());
  return ids.sort((a, b) => (a.memberId < b.memberId ? -1 : 1));
}

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
    assert.ok(await internals.addPinned({ alg: p.alg, pk: b64uEncode(p.pk), epk: b64uEncode(p.epk), name: "Peer" }));
    gens.push(await openGeneration({ seed: new Uint8Array(seed), g: 0, e0 }));
  }
  state.genRoster = new Set(state.pinned.keys());
  window.__starlingErrors.length = 0;
  return gens;
}

async function servedRekey(identity, gen, built) {
  const points = [];
  let ts = Date.now();
  for (const fields of built.posts) {
    ts += 1;
    const e = await gen.ratchet.currentEpoch(ts);
    const key = await gen.ratchet.keyFor(e, identity.memberId, ts);
    const sealed = await sealMessage(key, gen.channelId, identity.memberId, e, ts, { v: 2, ts, ...fields });
    const post = await buildPost(identity, gen.channelId, e, sealed, ts);
    points.push({ e: post.e, ts: post.ts, srv: post.ts, n: post.n, c: post.c, sig: post.sig });
  }
  return { m: identity.memberId, alg: identity.alg, pk: b64uEncode(identity.pk), epk: b64uEncode(identity.epk), points };
}

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

test("a removed member cannot re-key the circle back on the channel it left", async () => {
  // The removed member sorts first, so a tie-break on member id would hand the
  // circle to them if the window were open over a removal.
  const [gone, self, other] = await sortedIdentities(3);
  const [goneGen] = await circleWith(self, [gone, other]);
  const oldChannel = state.gen.channelId;

  // Their re-key wraps to everyone including themselves, built from the shared
  // generation, exactly as a rotation from the old channel would look.
  const byGone = await buildRekey({
    identity: gone,
    gen: goneGen,
    recipients: [rec(self), rec(other)],
    now: Date.now(),
  });
  const goneEntry = await servedRekey(gone, goneGen, byGone);
  const goneChannel = await channelOf(byGone);

  let landed = false;
  relay((chan) => (chan === oldChannel && landed ? [goneEntry] : []));
  await internals.enterCircle();
  await settle();

  assert.ok(await api.removeMember(gone.memberId), "the member was removed");
  const afterRemoval = state.gen.channelId;
  assert.notEqual(afterRemoval, oldChannel, "and the circle left the old channel");
  landed = true;

  // Longer than a poll, so a window that was open would have acted by now.
  await settle(12_000);
  harness.onFetch(null);

  assert.equal(state.gen.channelId, afterRemoval, "the circle stays where the removal put it");
  assert.notEqual(state.gen.channelId, goneChannel, "and never lands on the removed member's generation");
  assert.equal(state.pinned.has(gone.memberId), false, "the removed member is still out of the roster");
});
