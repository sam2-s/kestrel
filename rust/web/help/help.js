// The help page: a beacon viewer, in a browser, with no app and no account.
//
// What this does: reads a secret out of the URL fragment, derives a channel and
// a key from it, polls that channel, and draws the one person's positions it can
// decrypt. That is all. There is no registration, no storage, no service worker,
// no key here, and nothing sent to any server except the relay it is already
// talking to and, optionally, map tiles.
//
// The trust model is the part worth reading before the code. This page holds a
// *shared symmetric secret*: the same bytes the person in trouble holds. Anyone
// the link was ever forwarded to can therefore write a position that opens as
// cleanly as the real one, including a false location, or a "checked in safe"
// that ends the session while someone is still in trouble. Trust on first use
// would not help, because the attacker can be first: they hold the link before
// anything has been posted.
//
// What stops them is the signature. Every point is signed by a key whose member
// id is committed to in the link itself, and the id is derived from both of that
// keypair's public keys, so a relay cannot substitute a different key. This page
// accepts a point only from that member id, and checks the signature itself. A
// forger who derives the channel and the key from the link can produce a
// perfectly well-formed post, and it will be refused because the key that signed
// it is not the one the link names.
//
// So: the encryption keeps the position private from the relay, and the
// signature keeps the position honest. Neither alone would do both.

(() => {
  'use strict';

  // --- protocol constants, matching kestrel-core exactly ---

  const PROTO = 'starling/v2';
  const EPOCH_MS = 600000;
  const SKEW_EPOCHS = 2;
  const MEMBER_CAP = 16;
  const POLL_MS = 10000;
  const STALE_MS = 180000;
  const TRAIL_CAP = 240;
  const SESSION_KEY = 'kestrel-beacon';

  // The relay is this page's own origin, so a self-hosted relay needs no
  // configuration here at all.
  const RELAY = location.origin;

  // --- tiny helpers ---

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  function b64uDecode(s) {
    if (typeof s !== 'string' || s.length === 0) return null;
    if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
    // The final character of a 32 or 43 byte value carries two bits no byte
    // uses, so the same value has four spellings. Mask them off rather than
    // rejecting, exactly as the reference decoder does.
    let padded = s.replace(/-/g, '+').replace(/_/g, '/');
    padded += '='.repeat((4 - (padded.length % 4)) % 4);
    try {
      const raw = atob(padded);
      const out = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
      return out;
    } catch {
      return null;
    }
  }

  function b64uEncode(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  const hex = (bytes) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

  function unhex(s) {
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
    return out;
  }

  // --- key derivation: HKDF-SHA-256, salt of 32 zero bytes ---

  async function hkdf(ikm, info, length) {
    const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, [
      'deriveBits',
    ]);
    // An empty salt is not the same as 32 zero bytes, so the salt is passed
    // explicitly rather than omitted.
    const salt = new Uint8Array(32);
    return new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) },
        base,
        length * 8,
      ),
    );
  }

  const utf8 = (s) => new TextEncoder().encode(s);

  // --- link parsing ---

  function parseFragment(hash) {
    const body = hash.replace(/^#/, '').replace(/^b=/, '');
    const parts = body.split('.');
    if (parts.length !== 3) return null;

    const [secretS, expiresS, ownerS] = parts;
    if (secretS.length !== 43) return null;
    if (!/^\d{1,15}$/.test(expiresS)) return null;
    if (!/^[0-9a-f]{32}$/.test(ownerS)) return null;

    const secret = b64uDecode(secretS);
    if (!secret || secret.length !== 32) return null;

    return { secret, expiresAt: Number(expiresS), owner: ownerS };
  }

  // Read the secret, then take it out of the address bar.
  //
  // A fragment is never sent to a server, but it does sit in the address bar, in
  // the history, and in anything the user copies out of it. Moving it to
  // sessionStorage and rewriting the URL means a later screenshot of the address
  // bar shows nothing useful. Storage can be denied in private mode, and the page
  // still works for the session.
  function takeSecret() {
    let parsed = parseFragment(location.hash);
    if (!parsed) {
      try {
        const stored = sessionStorage.getItem(SESSION_KEY);
        if (stored) parsed = parseFragment(stored);
      } catch {
        /* storage denied; the fragment path is the common one */
      }
    } else {
      try {
        sessionStorage.setItem(SESSION_KEY, 'b=' + location.hash.slice(1));
        history.replaceState(null, '', location.pathname + location.search);
      } catch {
        /* not fatal */
      }
    }
    return parsed;
  }

  // --- the page's own state ---

  const state = {
    parsed: null,
    channel: null,
    key: null,
    cursor: 0,
    seen: new Set(),
    last: null,
    stopAt: 0,
    timer: null,
    tick: null,
  };

  // --- UI ---

  function showPanel(title, ...paragraphs) {
    const app = $('app');
    app.replaceChildren();
    const panel = el('div', 'panel');
    panel.append(el('h1', null, title));
    for (const p of paragraphs) panel.append(el('p', null, p));
    app.append(panel);
  }

  const STATUS_TEXT = {
    sos: 'Emergency active',
    sharing: 'Sharing live',
    'checked-in': 'Checked in safe',
    lost: 'No recent signal',
    stopped: 'Session ended',
  };

  function statusOf(last, now) {
    if (!last) return 'lost';
    // A goodbye never ages out. Telling a helper to keep watching for someone
    // who has already said they are safe is the wrong way to be wrong.
    if (last.t === 'bye') return 'stopped';
    if (now - last.ts > STALE_MS) return 'lost';
    if (last.t === 'sos') return 'sos';
    if (last.t === 'checkin') return 'checked-in';
    return 'sharing';
  }

  const privacyNote = () =>
    'This page decrypted the link on your device. The relay stored only ' +
    'ciphertext and cannot read it. Map tiles, if shown, are fetched from ' +
    'OpenStreetMap, which sees your address and the area of the emergency. ' +
    'The link is a shared secret: anyone it was forwarded to can read this ' +
    'page. If you were not expecting it, close the tab and tell the person who ' +
    'sent it.';

  // --- the map ---

  // A slippy-map tile grid, written out rather than pulled from a library: the
  // page needs a tile, a marker and a pan, and a library would be a hundred
  // kilobytes and a supply chain for three functions.
  const map = {
    el: null,
    marker: null,
    layer: null,
    z: 16,
    lat: 0,
    lon: 0,
    tiles: new Map(),
    ready: false,
  };

  const TILE = 256;

  function project(lat, lon, z) {
    const clamped = Math.max(-85.05112878, Math.min(85.05112878, lat));
    const n = TILE * Math.pow(2, z);
    return {
      x: ((lon + 180) / 360) * n,
      y:
        (0.5 -
          Math.log(Math.tan(Math.PI / 4 + (clamped * Math.PI) / 360)) /
            (2 * Math.PI)) *
        n,
    };
  }

  function ensureMap() {
    if (map.el) return;
    map.el = el('div', 'offgrid');
    map.el.id = 'map';
    map.marker = el('div', 'marker');
    map.marker.style.display = 'none';
    const attrib = el(
      'div',
      'attrib',
      '© OpenStreetMap contributors',
    );
    $('app').prepend(map.el, map.marker, attrib);
  }

  function draw() {
    if (!map.el || !state.last) return;
    const fix = state.last;
    if (fix.lat === undefined) return;

    map.lat = fix.lat;
    map.lon = fix.lon;
    const centre = project(fix.lat, fix.lon, map.z);
    const w = map.el.clientWidth;
    const h = map.el.clientHeight;
    map.el.style.backgroundPosition = `${-centre.x + w / 2}px ${-centre.y + h / 2}px`;

    map.marker.style.display = '';
    map.marker.style.left = `${w / 2}px`;
    map.marker.style.top = `${h / 2}px`;
    map.marker.dataset.status = statusOf(state.last, Date.now());

    if (!map.ready) loadTiles(centre, w, h);
  }

  // Tiles are fetched only while a position is being shown, and only for the
  // tiles the viewport actually covers. A helper who never opens the page
  // fetches nothing at all, which is the point of not having a service worker.
  function loadTiles(centre, w, h) {
    const z = Math.round(map.z);
    const scale = TILE * Math.pow(2, z) / (TILE * Math.pow(2, Math.round(map.z)));
    const zr = Math.round(map.z);
    if (zr !== z) return;

    const pad = 1;
    const x0 = Math.floor((centre.x - w / 2) / TILE) - pad;
    const x1 = Math.floor((centre.x + w / 2) / TILE) + pad;
    const y0 = Math.floor((centre.y - h / 2) / TILE) - pad;
    const y1 = Math.floor((centre.y + h / 2) / TILE) + pad;
    const n = Math.pow(2, zr);

    for (let ty = y0; ty <= y1; ty++) {
      for (let tx = x0; tx <= x1; tx++) {
        const wrapped = ((tx % n) + n) % n;
        const key = `${zr}/${wrapped}/${ty}`;
        if (map.tiles.has(key)) continue;
        map.tiles.set(key, null);
        const url = `https://tile.openstreetmap.org/${zr}/${wrapped}/${ty}.png`;
        const img = new Image();
        img.referrerPolicy = 'origin';
        img.onload = () => {
          const tile = map.tiles.get(key);
          if (tile) tile.src = url;
          else {
            // It arrived after the view moved on. Kept in a detached div so the
            // browser still decodes it and the next pan to this tile is instant.
            const t = el('div');
            t.style.backgroundImage = `url(${url})`;
            t.style.backgroundSize = '256px 256px';
            map.tiles.set(key, t);
          }
          applyLayer();
        };
        img.src = url;
      }
    }
    void scale;
    applyLayer();
  }

  function applyLayer() {
    if (!map.el) return;
    if (!map.layer) {
      map.layer = el('div');
      Object.assign(map.layer.style, {
        position: 'absolute',
        inset: '0',
        zIndex: '0',
        pointerEvents: 'none',
      });
      map.el.append(map.layer);
    }
    if (!map.ready) {
      map.ready = true;
      map.el.classList.remove('offgrid');
    }
    const w = map.el.clientWidth;
    const h = map.el.clientHeight;
    const centre = project(map.lat, map.lon, map.z);
    const zr = Math.round(map.z);
    const px = w / 2 - centre.x;
    const py = h / 2 - centre.y;

    map.layer.replaceChildren();
    for (const [key, node] of map.tiles) {
      const [z, x, y] = key.split('/').map(Number);
      if (z !== zr) continue;
      const tile = node || el('div');
      Object.assign(tile.style, {
        position: 'absolute',
        left: `${px + x * TILE}px`,
        top: `${py + y * TILE}px`,
        width: `${TILE}px`,
        height: `${TILE}px`,
        backgroundImage: node ? '' : 'none',
        filter: darkMode() ? 'invert(1) hue-rotate(180deg) brightness(0.95) contrast(0.9) saturate(0.38)' : '',
      });
      map.layer.append(tile);
    }
  }

  let darkQuery = null;
  function darkMode() {
    if (!darkQuery) darkQuery = matchMedia('(prefers-color-scheme: dark)');
    return darkQuery.matches;
  }

  // --- verification, on this device ---

  function algFromPk(pk) {
    if (pk.length === 32) return 'ed25519';
    if (pk.length === 65) return 'p256';
    return null;
  }

  async function verifySig(alg, pk, sig, message) {
    try {
      if (alg === 'ed25519') {
        const key = await crypto.subtle.importKey(
          'raw', pk, { name: 'Ed25519' }, false, ['verify'],
        );
        return await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, message);
      }
      if (alg === 'p256') {
        const key = await crypto.subtle.importKey(
          'raw', pk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'],
        );
        return await crypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' }, key, sig, message,
        );
      }
    } catch {
      return false;
    }
    return false;
  }

  const aad = (channel, member, e, ts) => `${PROTO}|${channel}|${member}|${e}|${ts}`;
  const sigBase = (channel, member, e, ts, n, c) =>
    `${PROTO}|${channel}|${member}|${e}|${ts}|${n}|${c}`;

  // Accept a point only from the member the link committed to, and only if the
  // signature is by the key that id is derived from. Both checks, in that order.
  async function accept(post, member) {
    if (post.m !== state.parsed.owner) return null;
    if (member.m !== state.parsed.owner) return null;

    const pk = b64uDecode(member.pk);
    const epk = b64uDecode(member.epk);
    const sig = b64uDecode(post.sig);
    const nonce = b64uDecode(post.n);
    const ct = b64uDecode(post.c);
    if (!pk || !epk || !sig || !nonce || !ct) return null;

    // The id must hash out of the keys, so a relay cannot present a keypair that
    // does not belong to the id it is offering.
    if ((await memberId(pk, epk)) !== post.m) return null;

    const alg = algFromPk(pk);
    if (!alg) return null;

    const base = sigBase(state.channel, post.m, post.e, post.ts, post.n, post.c);
    if (!(await verifySig(alg, pk, sig, utf8(base)))) return null;

    // Exactly one key is ever tried. AES-GCM is not key-committing, so trying
    // candidates and reporting which worked would be a partitioning oracle.
    const plain = await crypto.subtle
      .decrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: utf8(aad(state.channel, post.m, post.e, post.ts)) },
        state.key,
        ct,
      )
      .catch(() => null);
    if (!plain) return null;

    const body = JSON.parse(new TextDecoder().decode(plain));
    // The inner timestamp must match the header, so one message cannot claim two
    // different times.
    if (body.ts !== post.ts || body.v !== 2) return null;
    if (post.ts > Date.now() + 600000) return null;
    // A beacon is read-only. A control message here would be a way to move a
    // circle, which a help link must never become.
    if (body.t === 'rekey') return null;
    return body;
  }

  async function memberId(pk, epk) {
    const parts = new Uint8Array(utf8(`${PROTO}/member`).length + pk.length + epk.length);
    parts.set(utf8(`${PROTO}/member`), 0);
    parts.set(pk, utf8(`${PROTO}/member`).length);
    parts.set(epk, utf8(`${PROTO}/member`).length + pk.length);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', parts));
    return hex(digest.slice(0, 16));
  }

  // --- polling ---

  async function poll() {
    if (Date.now() >= state.stopAt) return finish(true);
    try {
      const res = await fetch(`${RELAY}/api/v2/f/${state.channel}?since=${state.cursor}`, {
        cache: 'no-store',
        redirect: 'error',
      });
      if (res.status === 410) return finish(true);
      if (!res.ok) throw new Error(String(res.status));

      const feed = await res.json();
      for (const member of feed.members) {
        for (const point of member.points) {
          // Deduplicate on the relay's own cursor, which is not unique per insert.
          const key = `${point.srv}|${member.m}|${point.e}|${point.ts}`;
          if (state.seen.has(key)) continue;
          state.seen.add(key);
          if (state.seen.size > 4096) {
            state.seen = new Set(Array.from(state.seen).slice(-2048));
          }
          if (point.srv < state.cursor) continue;
          state.cursor = Math.max(state.cursor, point.srv);

          const post = { m: member.m, alg: member.alg, pk: member.pk, epk: member.epk, ...point };
          const body = await accept(post, member);
          if (!body) continue;
          if (!state.last || body.ts >= state.last.ts) {
            state.last = body;
            render();
          }
        }
      }
    } catch {
      // A failed poll is retried on the next tick. Nothing is shown, because a
      // helper in an emergency needs a fact rather than an error.
    }
    if (Date.now() >= state.stopAt) finish(true);
  }

  function render() {
    const status = statusOf(state.last, Date.now());
    const app = $('app');
    if (!app.querySelector('.sheet')) {
      app.replaceChildren();
      ensureMap();
      const sheet = el('div', 'sheet');
      sheet.append(
        el('div', 'status'),
        el('div', 'where'),
        el('div', 'when'),
        el('div', 'privacy'),
      );
      $('app').append(sheet);
    }
    const sheet = app.querySelector('.sheet');
    const statusEl = sheet.querySelector('.status');
    statusEl.dataset.status = status;
    statusEl.textContent = STATUS_TEXT[status];

    const where = sheet.querySelector('.where');
    if (state.last && state.last.lat !== undefined) {
      where.textContent = `${state.last.lat.toFixed(4)}, ${state.last.lon.toFixed(4)}`;
    } else {
      where.textContent = '';
    }

    const when = sheet.querySelector('.when');
    if (state.last) {
      const age = Math.max(0, Math.round((Date.now() - state.last.ts) / 1000));
      when.textContent =
        age < 90
          ? `updated ${age} seconds ago`
          : `updated ${Math.round(age / 60)} minutes ago`;
    }

    if (!sheet.querySelector('.privacy').textContent) {
      sheet.querySelector('.privacy').textContent = privacyNote();
    }
    draw();
  }

  function finish(expired) {
    if (state.timer) clearTimeout(state.timer);
    if (state.tick) clearInterval(state.tick);
    state.timer = null;
    state.tick = null;
    showPanel(
      expired ? 'This help link has expired' : 'Session ended',
      expired
        ? 'The emergency is over, or the link reached its time limit. Nothing is kept: the relay deletes every row after a day, and this page stored nothing.'
        : 'The person using this link checked in safe, so it has been switched off.',
    );
  }

  async function start() {
    const parsed = takeSecret();
    if (!parsed) {
      showPanel(
        'Not a valid help link',
        'This page opens from a link someone sent you. If you followed one and landed here, the link may have been cut short when it was copied.',
      );
      return;
    }
    if (Date.now() >= parsed.expiresAt) {
      showPanel(
        'This help link has expired',
        'The emergency it pointed to is over. Nothing is kept.',
      );
      return;
    }

    state.parsed = parsed;
    state.stopAt = parsed.expiresAt;
    state.channel = hex(await hkdf(parsed.secret, `${PROTO}/help-channel-id`, 16));
    state.key = await crypto.subtle.importKey(
      'raw',
      await hkdf(parsed.secret, `${PROTO}/help-enc`, 32),
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    );

    const app = $('app');
    app.replaceChildren();
    ensureMap();
    const sheet = el('div', 'sheet');
    sheet.append(
      el('div', 'status'),
      el('div', 'where'),
      el('div', 'when'),
      el('div', 'privacy'),
    );
    app.append(sheet);
    render();

    state.timer = setTimeout(() => poll(), 0);
    // A fifteen second tick drives the staleness line and re-checks expiry. The
    // timer schedule is rescheduled in hops, because a delay larger than a signed
    // 32-bit millisecond count overflows and fires immediately.
    const schedule = () => {
      if (state.timer) clearTimeout(state.timer);
      const remaining = state.stopAt - Date.now();
      if (remaining <= 0) return finish(true);
      state.timer = setTimeout(async () => {
        await poll();
        schedule();
      }, Math.min(remaining, 0x7fffffff));
    };
    schedule();
    state.tick = setInterval(() => {
      render();
      if (Date.now() >= state.stopAt) finish(true);
    }, 15000);

    addEventListener('hashchange', () => location.reload());
    addEventListener('resize', () => {
      applyLayer();
      draw();
    });
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && Date.now() < state.stopAt) poll();
    });
  }

  start();
})();
