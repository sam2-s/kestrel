// The advisory health probe behind the relay setting: a saved URL that does
// not answer must warn without refusing, because the value is stored before
// the probe runs. fetch is stubbed; no request leaves the process.
import test from "node:test";
import assert from "node:assert/strict";
import { relayReachable } from "../app/js/env.js";

function withFetch(stub, fn) {
  const prev = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return stub(url, init);
  };
  try {
    return fn(calls);
  } finally {
    globalThis.fetch = prev;
  }
}

function reply({ status = 200, body } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => {
      if (body === undefined) throw new Error("no body");
      return body;
    },
  };
}

const BASE = "https://relay.example.org/starling";

test("reaches for the health endpoint of exactly the base it was given", async () => {
  withFetch(
    () => reply({ body: { ok: true } }),
    async (calls) => {
      assert.equal(await relayReachable(BASE), true);
      assert.equal(calls.length, 1);
      assert.equal(calls[0].url, `${BASE}/api/v2/health`);
      assert.equal(calls[0].init.cache, "no-store");
      assert.ok(calls[0].init.signal, "a timeout signal must be armed");
    },
  );
});

test("only an explicit ok:true counts as reachable", async () => {
  await withFetch(() => reply({ body: { ok: false } }), async () => {
    assert.equal(await relayReachable(BASE), false);
  });
  await withFetch(() => reply({ body: {} }), async () => {
    assert.equal(await relayReachable(BASE), false);
  });
});

test("an HTTP error status is not reachable", async () => {
  await withFetch(() => reply({ status: 500, body: { ok: true } }), async () => {
    assert.equal(await relayReachable(BASE), false);
  });
  await withFetch(() => reply({ status: 403 }), async () => {
    assert.equal(await relayReachable(BASE), false);
  });
});

test("network failure and an unreadable body both read as unreachable", async () => {
  await withFetch(
    () => {
      throw new Error("connection refused");
    },
    async () => {
      assert.equal(await relayReachable(BASE), false);
    },
  );
  await withFetch(() => reply({ body: undefined }), async () => {
    assert.equal(await relayReachable(BASE), false);
  });
});
