// QR decoder for the safety-number scan. A camera frame comes in as
// ImageData (RGBA) or as 8-bit grayscale and the text comes out, or null.
// Versions 1-10, all four error correction levels, byte, numeric and
// alphanumeric modes. No camera code here: this is a pure function of the
// pixels, which is what makes it testable from Node against python qrcode
// renders (test/qrscan.test.mjs).
//
// The pipeline is the classic one: threshold in blocks, find the three
// finder patterns by their 1:1:3:1:1 runs, estimate the size, refine the
// fourth corner on the bottom-right alignment pattern, map every module
// center through a homography, read the format info, unmask, de-interleave
// the blocks, correct with Reed-Solomon and parse the bit stream.

import { ALIGN_POS, GF_EXP, GF_LOG, MASKS, RS_BLOCKS, bchTypeInfo, bchTypeNumber } from "./qr.js";

const MIN_DIM = 21;
const MAX_DIM = 57;
const BLOCK = 8;

// ------------------------------------------------------------ luminance

function toGray(img) {
  const w = img?.width | 0;
  const h = img?.height | 0;
  const data = img?.data;
  if (w <= 0 || h <= 0 || !data || typeof data.length !== "number") return null;
  if (data.length === w * h) return data instanceof Uint8Array ? data : Uint8Array.from(data);
  if (data.length !== w * h * 4) return null;
  const g = new Uint8Array(w * h);
  for (let i = 0, j = 0; i < g.length; i++, j += 4) {
    g[i] = (data[j] * 77 + data[j + 1] * 151 + data[j + 2] * 28) >> 8;
  }
  return g;
}

// ------------------------------------------------------------- threshold

// Block-local threshold. Each 8x8 block gets a black point from its own
// range, a flat block borrows its darker neighbors' point so the inside of
// a finder stays dark, and a pixel is compared against the 5x5 block
// neighborhood's average so uneven lighting across the frame does not matter.
// A 3x3 box blur first. Camera noise defeats the flat-block test below (a
// noisy white patch has range enough to look like signal, so its threshold
// lands just under white and the quiet zone turns to speckle); averaging nine
// pixels takes the noise down by three while a module of three pixels or more
// keeps its center.
function smooth(gray, w, h) {
  const tmp = new Uint16Array(w * h);
  for (let y = 0; y < h; y++) {
    const row = y * w;
    for (let x = 0; x < w; x++) {
      const l = x > 0 ? x - 1 : x;
      const r = x < w - 1 ? x + 1 : x;
      tmp[row + x] = gray[row + l] + gray[row + x] + gray[row + r];
    }
  }
  const out = new Uint8Array(w * h);
  for (let y = 0; y < h; y++) {
    const up = (y > 0 ? y - 1 : y) * w;
    const mid = y * w;
    const down = (y < h - 1 ? y + 1 : y) * w;
    for (let x = 0; x < w; x++) out[mid + x] = (tmp[up + x] + tmp[mid + x] + tmp[down + x]) / 9;
  }
  return out;
}

function binarize(raw, w, h) {
  const gray = smooth(raw, w, h);
  const bits = new Uint8Array(w * h);
  const bw = Math.ceil(w / BLOCK);
  const bh = Math.ceil(h / BLOCK);
  let gmin = 255;
  let gmax = 0;
  for (let i = 0; i < gray.length; i++) {
    if (gray[i] < gmin) gmin = gray[i];
    if (gray[i] > gmax) gmax = gray[i];
  }
  const flat = Math.max(24, (gmax - gmin) * 0.3);
  if (bw < 5 || bh < 5) {
    const thr = (gmin + gmax) / 2;
    for (let i = 0; i < gray.length; i++) if (gray[i] <= thr) bits[i] = 1;
    return bits;
  }
  const points = new Int32Array(bw * bh);
  for (let by = 0; by < bh; by++) {
    const y0 = Math.min(by * BLOCK, h - BLOCK);
    for (let bx = 0; bx < bw; bx++) {
      const x0 = Math.min(bx * BLOCK, w - BLOCK);
      let sum = 0;
      let min = 255;
      let max = 0;
      for (let yy = 0; yy < BLOCK; yy++) {
        let o = (y0 + yy) * w + x0;
        for (let xx = 0; xx < BLOCK; xx++, o++) {
          const p = gray[o];
          sum += p;
          if (p < min) min = p;
          if (p > max) max = p;
        }
      }
      let avg = sum >> 6;
      if (max - min <= flat) {
        avg = min >> 1;
        if (by > 0 && bx > 0) {
          const nb =
            (points[(by - 1) * bw + bx] + 2 * points[by * bw + bx - 1] + points[(by - 1) * bw + bx - 1]) >> 2;
          if (min < nb) avg = nb;
        }
      }
      points[by * bw + bx] = avg;
    }
  }
  for (let by = 0; by < bh; by++) {
    const y0 = Math.min(by * BLOCK, h - BLOCK);
    const top = Math.min(Math.max(by, 2), bh - 3);
    for (let bx = 0; bx < bw; bx++) {
      const x0 = Math.min(bx * BLOCK, w - BLOCK);
      const left = Math.min(Math.max(bx, 2), bw - 3);
      let sum = 0;
      for (let z = -2; z <= 2; z++) {
        const row = (top + z) * bw + left;
        sum += points[row - 2] + points[row - 1] + points[row] + points[row + 1] + points[row + 2];
      }
      const thr = sum / 25;
      for (let yy = 0; yy < BLOCK; yy++) {
        let o = (y0 + yy) * w + x0;
        for (let xx = 0; xx < BLOCK; xx++, o++) if (gray[o] <= thr) bits[o] = 1;
      }
    }
  }
  return bits;
}

// --------------------------------------------------------- finder search

// tolerance: 2 for the row scan (half a module either way), looser for the
// cross-checks, where a blurred ring edge lands a pixel off.
function runsLookLikeFinder(sc, tolerance) {
  let total = 0;
  for (let i = 0; i < 5; i++) {
    if (sc[i] === 0) return false;
    total += sc[i];
  }
  if (total < 7) return false;
  const ms = total / 7;
  const v = ms / tolerance;
  return (
    Math.abs(ms - sc[0]) < v &&
    Math.abs(ms - sc[1]) < v &&
    Math.abs(3 * ms - sc[2]) < 3 * v &&
    Math.abs(ms - sc[3]) < v &&
    Math.abs(ms - sc[4]) < v
  );
}

const centerFromEnd = (sc, end) => end - sc[4] - sc[3] - sc[2] / 2;

class Finders {
  constructor(bits, w, h) {
    this.bits = bits;
    this.w = w;
    this.h = h;
    this.found = [];
  }

  dark(x, y) {
    return this.bits[y * this.w + x] === 1;
  }

  // Walk out from a candidate center along one axis and check the same
  // 1:1:3:1:1 proportions hold there, returning the refined center or NaN.
  crossCheck(start, fixed, vertical, maxCount, originalTotal) {
    const sc = [0, 0, 0, 0, 0];
    const limit = vertical ? this.h : this.w;
    const at = (i) => (vertical ? this.dark(fixed, i) : this.dark(i, fixed));
    let i = start;
    while (i >= 0 && at(i)) {
      sc[2]++;
      i--;
    }
    if (i < 0) return NaN;
    while (i >= 0 && !at(i) && sc[1] <= maxCount) {
      sc[1]++;
      i--;
    }
    if (i < 0 || sc[1] > maxCount) return NaN;
    while (i >= 0 && at(i) && sc[0] <= maxCount) {
      sc[0]++;
      i--;
    }
    if (sc[0] > maxCount) return NaN;
    i = start + 1;
    while (i < limit && at(i)) {
      sc[2]++;
      i++;
    }
    if (i === limit) return NaN;
    while (i < limit && !at(i) && sc[3] < maxCount) {
      sc[3]++;
      i++;
    }
    if (i === limit || sc[3] >= maxCount) return NaN;
    while (i < limit && at(i) && sc[4] < maxCount) {
      sc[4]++;
      i++;
    }
    if (sc[4] >= maxCount) return NaN;
    const total = sc[0] + sc[1] + sc[2] + sc[3] + sc[4];
    if (5 * Math.abs(total - originalTotal) >= 2 * originalTotal) return NaN;
    return runsLookLikeFinder(sc, 1.5) ? centerFromEnd(sc, i) : NaN;
  }

  crossCheckDiagonal(cy, cx) {
    const sc = [0, 0, 0, 0, 0];
    let i = 0;
    while (cy >= i && cx >= i && this.dark(cx - i, cy - i)) {
      sc[2]++;
      i++;
    }
    if (sc[2] === 0) return false;
    while (cy >= i && cx >= i && !this.dark(cx - i, cy - i)) {
      sc[1]++;
      i++;
    }
    if (sc[1] === 0) return false;
    while (cy >= i && cx >= i && this.dark(cx - i, cy - i)) {
      sc[0]++;
      i++;
    }
    if (sc[0] === 0) return false;
    i = 1;
    while (cy + i < this.h && cx + i < this.w && this.dark(cx + i, cy + i)) {
      sc[2]++;
      i++;
    }
    while (cy + i < this.h && cx + i < this.w && !this.dark(cx + i, cy + i)) {
      sc[3]++;
      i++;
    }
    if (sc[3] === 0) return false;
    while (cy + i < this.h && cx + i < this.w && this.dark(cx + i, cy + i)) {
      sc[4]++;
      i++;
    }
    if (sc[4] === 0) return false;
    return runsLookLikeFinder(sc, 1.333);
  }

  consider(sc, y, endX) {
    const total = sc[0] + sc[1] + sc[2] + sc[3] + sc[4];
    let cx = centerFromEnd(sc, endX);
    let cy = this.crossCheck(y, Math.floor(cx), true, sc[2], total);
    if (Number.isNaN(cy)) return;
    cx = this.crossCheck(Math.floor(cx), Math.floor(cy), false, sc[2], total);
    if (Number.isNaN(cx)) return;
    if (!this.crossCheckDiagonal(Math.floor(cy), Math.floor(cx))) return;
    const ms = total / 7;
    for (const p of this.found) {
      const dms = Math.abs(p.ms - ms);
      if (Math.abs(p.y - cy) <= ms && Math.abs(p.x - cx) <= ms && (dms <= 1 || dms <= p.ms)) {
        const n = p.count + 1;
        p.x = (p.count * p.x + cx) / n;
        p.y = (p.count * p.y + cy) / n;
        p.ms = (p.count * p.ms + ms) / n;
        p.count = n;
        return;
      }
    }
    this.found.push({ x: cx, y: cy, ms, count: 1 });
  }

  scan() {
    const { bits, w, h } = this;
    const sc = [0, 0, 0, 0, 0];
    const step = h > 700 ? 2 : 1;
    for (let y = 0; y < h; y += step) {
      sc.fill(0);
      let state = 0;
      const row = y * w;
      for (let x = 0; x < w; x++) {
        if (bits[row + x]) {
          if (state & 1) state++;
          sc[state]++;
        } else if (state & 1) {
          sc[state]++;
        } else if (state === 4) {
          if (runsLookLikeFinder(sc, 2)) this.consider(sc, y, x);
          sc[0] = sc[2];
          sc[1] = sc[3];
          sc[2] = sc[4];
          sc[3] = 1;
          sc[4] = 0;
          state = 3;
        } else {
          sc[++state]++;
        }
      }
      if (state === 4 && runsLookLikeFinder(sc, 2)) this.consider(sc, y, w);
    }
    return this.found;
  }
}

const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

// Every way of picking three of the strongest candidates, ordered by how
// much each triple looks like the corners of a square: two equal legs at a
// right angle, similar module sizes. The corner opposite the long side is
// the top-left finder; the other two are told apart by the turn direction,
// so a mirrored arrangement is never read as a code.
function orderTriples(found) {
  if (found.length < 3) return [];
  const top = [...found].sort((a, b) => b.count - a.count).slice(0, 8);
  const out = [];
  for (let i = 0; i < top.length; i++) {
    for (let j = i + 1; j < top.length; j++) {
      for (let k = j + 1; k < top.length; k++) {
        const pts = [top[i], top[j], top[k]];
        const d = [dist(pts[1], pts[2]), dist(pts[0], pts[2]), dist(pts[0], pts[1])];
        let tl = 0;
        for (let m = 1; m < 3; m++) if (d[m] > d[tl]) tl = m;
        const a = pts[tl];
        const others = pts.filter((_, m) => m !== tl);
        const l1 = dist(a, others[0]);
        const l2 = dist(a, others[1]);
        if (l1 === 0 || l2 === 0) continue;
        const hyp = d[tl];
        const ms = (pts[0].ms + pts[1].ms + pts[2].ms) / 3;
        const modules = (l1 + l2) / 2 / ms + 7;
        if (modules < MIN_DIM - 4 || modules > MAX_DIM + 6) continue;
        const msSpread = Math.max(...pts.map((p) => Math.abs(p.ms - ms))) / ms;
        const score =
          Math.abs(l1 - l2) / Math.max(l1, l2) +
          Math.abs(hyp - Math.SQRT2 * ((l1 + l2) / 2)) / hyp +
          msSpread;
        const cross = (others[0].x - a.x) * (others[1].y - a.y) - (others[0].y - a.y) * (others[1].x - a.x);
        const [tr, bl] = cross > 0 ? others : [others[1], others[0]];
        out.push({ score, tl: a, tr, bl, ms });
      }
    }
  }
  return out.sort((a, b) => a.score - b.score);
}

// ------------------------------------------------------ alignment search

// The bottom-right alignment pattern: a dark module ringed by light ringed
// by dark, so a scanline through its middle reads light, dark, light in
// 1:1:1. Every cross-confirmed candidate in the window is then scored
// against the full 5x5 pattern, because an isolated dark data module gives
// the same 1:1:1 on both axes and a window wide enough to survive a tilt
// holds plenty of those.
function findAlignment(bits, w, h, cx, cy, ms, allowance) {
  const left = Math.max(0, Math.floor(cx - allowance));
  const right = Math.min(w, Math.ceil(cx + allowance));
  const top = Math.max(0, Math.floor(cy - allowance));
  const bottom = Math.min(h, Math.ceil(cy + allowance));
  if (right - left < 3 * ms || bottom - top < 3 * ms) return null;
  const dark = (x, y) => x >= 0 && y >= 0 && x < w && y < h && bits[y * w + x] === 1;
  const looks = (sc) => {
    const v = ms / 2;
    return Math.abs(ms - sc[0]) < v && Math.abs(ms - sc[1]) < v && Math.abs(ms - sc[2]) < v;
  };
  const vertical = (startY, x, maxCount, originalTotal) => {
    const sc = [0, 0, 0];
    let i = startY;
    while (i >= 0 && dark(x, i) && sc[1] <= maxCount) {
      sc[1]++;
      i--;
    }
    if (i < 0 || sc[1] > maxCount) return NaN;
    while (i >= 0 && !dark(x, i) && sc[0] <= maxCount) {
      sc[0]++;
      i--;
    }
    if (sc[0] > maxCount) return NaN;
    i = startY + 1;
    while (i < h && dark(x, i) && sc[1] <= maxCount) {
      sc[1]++;
      i++;
    }
    if (i === h || sc[1] > maxCount) return NaN;
    while (i < h && !dark(x, i) && sc[2] <= maxCount) {
      sc[2]++;
      i++;
    }
    if (sc[2] > maxCount) return NaN;
    const total = sc[0] + sc[1] + sc[2];
    if (5 * Math.abs(total - originalTotal) >= 2 * originalTotal) return NaN;
    return looks(sc) ? i - sc[2] - sc[1] / 2 : NaN;
  };
  const candidates = [];
  const consider = (sc, y, endX) => {
    const total = sc[0] + sc[1] + sc[2];
    const px = endX - sc[2] - sc[1] / 2;
    const py = vertical(y, Math.floor(px), 2 * sc[1], total);
    if (Number.isNaN(py)) return;
    const est = total / 3;
    for (const c of candidates) {
      if (Math.abs(c.y - py) <= ms && Math.abs(c.x - px) <= ms && Math.abs(c.ms - est) <= Math.max(1, ms)) {
        c.x = (c.x * c.n + px) / (c.n + 1);
        c.y = (c.y * c.n + py) / (c.n + 1);
        c.ms = (c.ms * c.n + est) / (c.n + 1);
        c.n++;
        return;
      }
    }
    candidates.push({ x: px, y: py, ms: est, n: 1 });
  };
  for (let y = top; y < bottom; y++) {
    const sc = [0, 0, 0];
    let x = left;
    while (x < right && !dark(x, y)) x++;
    let state = 0;
    while (x < right) {
      if (dark(x, y)) {
        if (state === 1) sc[1]++;
        else if (state === 2) {
          if (looks(sc)) consider(sc, y, x);
          sc[0] = sc[2];
          sc[1] = 1;
          sc[2] = 0;
          state = 1;
        } else {
          sc[++state]++;
        }
      } else {
        if (state === 1) state++;
        sc[state]++;
      }
      x++;
    }
    if (looks(sc)) consider(sc, y, right);
  }
  let best = null;
  for (const c of candidates) {
    let hits = 0;
    for (let i = -2; i <= 2; i++) {
      for (let j = -2; j <= 2; j++) {
        const want = Math.abs(i) === 2 || Math.abs(j) === 2 || (i === 0 && j === 0);
        if (dark(Math.round(c.x + j * c.ms), Math.round(c.y + i * c.ms)) === want) hits++;
      }
    }
    const away = Math.hypot(c.x - cx, c.y - cy);
    if (hits < 22) continue;
    if (!best || hits > best.hits || (hits === best.hits && away < best.away)) best = { x: c.x, y: c.y, hits, away };
  }
  return best;
}

// ------------------------------------------------------------ homography

// The 3x3 map from module space to pixels, from four point pairs, by
// solving the eight linear equations directly.
function homography(src, dst) {
  const m = [];
  for (let i = 0; i < 4; i++) {
    const [u, v] = src[i];
    const [x, y] = dst[i];
    m.push([u, v, 1, 0, 0, 0, -u * x, -v * x, x]);
    m.push([0, 0, 0, u, v, 1, -u * y, -v * y, y]);
  }
  for (let c = 0; c < 8; c++) {
    let pivot = c;
    for (let r = c + 1; r < 8; r++) if (Math.abs(m[r][c]) > Math.abs(m[pivot][c])) pivot = r;
    if (Math.abs(m[pivot][c]) < 1e-12) return null;
    [m[c], m[pivot]] = [m[pivot], m[c]];
    for (let r = 0; r < 8; r++) {
      if (r === c) continue;
      const f = m[r][c] / m[c][c];
      if (f === 0) continue;
      for (let k = c; k <= 8; k++) m[r][k] -= f * m[c][k];
    }
  }
  const hm = m.map((row, i) => row[8] / row[i]);
  return (u, v) => {
    const d = hm[6] * u + hm[7] * v + 1;
    return [(hm[0] * u + hm[1] * v + hm[2]) / d, (hm[3] * u + hm[4] * v + hm[5]) / d];
  };
}

// Where the plane puts a module point, from the three finders alone. Under
// a homography the module size at a point falls with w^(3/2), w being the
// projective denominator, and w is linear in module coordinates, so the
// three finder sizes fix how the plane recedes and the three centers fix
// the rest. Falls back to the parallelogram when the sizes do not add up.
function finderMap(tri, dim) {
  const { tl, tr, bl } = tri;
  const n = dim - 7;
  const kTr = Math.pow(tl.ms / tr.ms, 2 / 3);
  const kBl = Math.pow(tl.ms / bl.ms, 2 / 3);
  let wTl = 1 / (1 - (3.5 * (kTr + kBl - 2)) / n);
  let h6 = (wTl * (kTr - 1)) / n;
  let h7 = (wTl * (kBl - 1)) / n;
  if (!(wTl > 0.2 && wTl < 5) || !Number.isFinite(h6) || !Number.isFinite(h7)) {
    wTl = 1;
    h6 = 0;
    h7 = 0;
  }
  const wTr = wTl + h6 * n;
  const wBl = wTl + h7 * n;
  const h0 = (tr.x * wTr - tl.x * wTl) / n;
  const h1 = (bl.x * wBl - tl.x * wTl) / n;
  const h2 = tl.x * wTl - 3.5 * (h0 + h1);
  const h3 = (tr.y * wTr - tl.y * wTl) / n;
  const h4 = (bl.y * wBl - tl.y * wTl) / n;
  const h5 = tl.y * wTl - 3.5 * (h3 + h4);
  return (u, v) => {
    const d = h6 * u + h7 * v + 1;
    if (!(d > 0.05)) return [tl.x + ((u - 3.5) / n) * (tr.x - tl.x) + ((v - 3.5) / n) * (bl.x - tl.x), tl.y + ((u - 3.5) / n) * (tr.y - tl.y) + ((v - 3.5) / n) * (bl.y - tl.y)];
    return [(h0 * u + h1 * v + h2) / d, (h3 * u + h4 * v + h5) / d];
  };
}

function transformWith(tri, dim, fourth, fourthPixel) {
  const { tl, tr, bl } = tri;
  return homography(
    [
      [3.5, 3.5],
      [dim - 3.5, 3.5],
      [3.5, dim - 3.5],
      fourth,
    ],
    [
      [tl.x, tl.y],
      [tr.x, tr.y],
      [bl.x, bl.y],
      fourthPixel,
    ],
  );
}

// The fourth anchor: the alignment pattern when the version has one and the
// search finds it, else the finder-derived guess for the bottom-right
// finder-sized corner.
function fourthAnchor(bits, w, h, tri, dim, useAlignment) {
  const guess = finderMap(tri, dim);
  const version = (dim - 17) / 4;
  if (useAlignment) {
    if (version < 2) return null;
    const [ex, ey] = guess(dim - 6.5, dim - 6.5);
    const ms = Math.max(1, (tri.tr.ms * tri.bl.ms) / tri.tl.ms);
    for (const factor of [4, 8, 16]) {
      const hit = findAlignment(bits, w, h, ex, ey, ms, factor * ms);
      if (hit) return { point: [dim - 6.5, dim - 6.5], pixel: [hit.x, hit.y] };
    }
    return null;
  }
  return { point: [dim - 3.5, dim - 3.5], pixel: guess(dim - 3.5, dim - 3.5) };
}

function sampleGrid(bits, w, h, map, dim) {
  const grid = new Uint8Array(dim * dim);
  for (let y = 0; y < dim; y++) {
    for (let x = 0; x < dim; x++) {
      const [px, py] = map(x + 0.5, y + 0.5);
      if (!(px >= -1 && px <= w && py >= -1 && py <= h)) return null;
      const ix = Math.min(w - 1, Math.max(0, Math.floor(px)));
      const iy = Math.min(h - 1, Math.max(0, Math.floor(py)));
      grid[y * dim + x] = bits[iy * w + ix];
    }
  }
  return grid;
}

// How well row 6 and column 6 alternate between the finders. Used to rank
// candidate sizes, since the finders alone place the size within a version
// or two.
function timingScore(grid, dim) {
  let ok = 0;
  let n = 0;
  for (let i = 8; i < dim - 8; i++) {
    const want = i % 2 === 0 ? 1 : 0;
    if (grid[6 * dim + i] === want) ok++;
    if (grid[i * dim + 6] === want) ok++;
    n += 2;
  }
  return n ? ok / n : 0;
}

// ---------------------------------------------------------- format info

const ECC_NAMES = ["M", "L", "H", "Q"];

function popcount(x) {
  let n = 0;
  while (x) {
    x &= x - 1;
    n++;
  }
  return n;
}

function readFormat(grid, dim) {
  const get = (r, c) => grid[r * dim + c];
  let a = 0;
  let b = 0;
  for (let i = 0; i < 15; i++) {
    const r1 = i < 6 ? i : i < 8 ? i + 1 : dim - 15 + i;
    a |= get(r1, 8) << i;
    const c2 = i < 8 ? dim - i - 1 : i < 9 ? 15 - i : 14 - i;
    b |= get(8, c2) << i;
  }
  let best = null;
  for (let data = 0; data < 32; data++) {
    const want = bchTypeInfo(data);
    const d = Math.min(popcount(a ^ want), popcount(b ^ want));
    if (!best || d < best.d) best = { d, data };
  }
  if (!best || best.d > 3) return null;
  return { ecc: ECC_NAMES[best.data >> 3], mask: best.data & 7 };
}

function readVersion(grid, dim) {
  const get = (r, c) => grid[r * dim + c];
  let a = 0;
  let b = 0;
  for (let i = 0; i < 18; i++) {
    a |= get(Math.floor(i / 3), (i % 3) + dim - 11) << i;
    b |= get((i % 3) + dim - 11, Math.floor(i / 3)) << i;
  }
  let best = null;
  for (let v = 7; v <= 40; v++) {
    const want = bchTypeNumber(v);
    const d = Math.min(popcount(a ^ want), popcount(b ^ want));
    if (!best || d < best.d) best = { d, v };
  }
  return best && best.d <= 3 ? best.v : null;
}

// ----------------------------------------------------- function modules

function functionMask(version, dim) {
  const f = new Uint8Array(dim * dim);
  const fill = (r0, r1, c0, c1) => {
    for (let r = r0; r <= r1; r++) for (let c = c0; c <= c1; c++) f[r * dim + c] = 1;
  };
  fill(0, 8, 0, 8);
  fill(0, 8, dim - 8, dim - 1);
  fill(dim - 8, dim - 1, 0, 8);
  // Before the timing lines: an alignment pattern that sits on one (from
  // version 7 up) is still an alignment pattern, only one inside a finder is not.
  for (const r of ALIGN_POS[version]) {
    for (const c of ALIGN_POS[version]) {
      if (f[r * dim + c]) continue;
      fill(r - 2, r + 2, c - 2, c + 2);
    }
  }
  for (let i = 0; i < dim; i++) {
    f[6 * dim + i] = 1;
    f[i * dim + 6] = 1;
  }
  if (version >= 7) {
    fill(0, 5, dim - 11, dim - 9);
    fill(dim - 11, dim - 9, 0, 5);
  }
  return f;
}

function readCodewords(grid, dim, version, mask, total) {
  const func = functionMask(version, dim);
  const mf = MASKS[mask];
  const out = new Uint8Array(total);
  let byteIndex = 0;
  let bitIndex = 7;
  let row = dim - 1;
  let inc = -1;
  for (let start = dim - 1; start > 0 && byteIndex < total; start -= 2) {
    let col = start;
    if (col <= 6) col -= 1;
    for (;;) {
      for (const c of [col, col - 1]) {
        if (func[row * dim + c] || byteIndex >= total) continue;
        let bit = grid[row * dim + c];
        if (mf(row, c)) bit ^= 1;
        if (bit) out[byteIndex] |= 1 << bitIndex;
        bitIndex--;
        if (bitIndex < 0) {
          byteIndex++;
          bitIndex = 7;
        }
      }
      row += inc;
      if (row < 0 || row >= dim) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
  return byteIndex >= total ? out : null;
}

// --------------------------------------------------------- Reed-Solomon

const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]);
const gfInv = (a) => GF_EXP[(255 - GF_LOG[a]) % 255];

function polyEval(p, x) {
  let v = 0;
  for (let i = p.length - 1; i >= 0; i--) v = gfMul(v, x) ^ p[i];
  return v;
}

// Corrects cw in place. Returns the number of errors fixed, or -1 when there
// are more than the block can carry. Syndromes, Berlekamp-Massey for the
// locator, a root search over the block's positions, Forney for the values,
// and the syndromes again afterwards so a wrong fix never passes as a right one.
function rsCorrect(cw, ec) {
  const n = cw.length;
  const synd = new Uint8Array(ec);
  let clean = true;
  for (let j = 0; j < ec; j++) {
    const x = GF_EXP[j % 255];
    let s = 0;
    for (let i = 0; i < n; i++) s = gfMul(s, x) ^ cw[i];
    synd[j] = s;
    if (s) clean = false;
  }
  if (clean) return 0;

  let C = [1];
  let B = [1];
  let L = 0;
  let m = 1;
  let b = 1;
  for (let k = 0; k < ec; k++) {
    let d = synd[k];
    for (let i = 1; i <= L; i++) d ^= gfMul(C[i] || 0, synd[k - i]);
    if (d === 0) {
      m++;
      continue;
    }
    const coef = gfMul(d, gfInv(b));
    const next = C.slice();
    for (let i = 0; i < B.length; i++) {
      const idx = i + m;
      while (next.length <= idx) next.push(0);
      next[idx] ^= gfMul(coef, B[i]);
    }
    if (2 * L <= k) {
      L = k + 1 - L;
      B = C;
      b = d;
      m = 1;
    } else {
      m++;
    }
    C = next;
  }
  if (2 * L > ec) return -1;
  while (C.length < L + 1) C.push(0);
  C.length = L + 1;

  const positions = [];
  for (let i = 0; i < n; i++) {
    if (polyEval(C, GF_EXP[(255 - (i % 255)) % 255]) === 0) positions.push(i);
  }
  if (positions.length !== L) return -1;

  const omega = new Array(ec).fill(0);
  for (let i = 0; i < ec; i++) {
    for (let j = 0; j <= L && i + j < ec; j++) omega[i + j] ^= gfMul(synd[i], C[j]);
  }
  const deriv = [];
  for (let i = 1; i <= L; i += 2) {
    deriv[i - 1] = C[i];
    if (i < L) deriv[i] = 0;
  }
  for (const i of positions) {
    const xinv = GF_EXP[(255 - (i % 255)) % 255];
    const den = polyEval(deriv, xinv);
    if (den === 0) return -1;
    const mag = gfMul(GF_EXP[i % 255], gfMul(polyEval(omega, xinv), gfInv(den)));
    cw[n - 1 - i] ^= mag;
  }
  for (let j = 0; j < ec; j++) {
    const x = GF_EXP[j % 255];
    let s = 0;
    for (let i = 0; i < n; i++) s = gfMul(s, x) ^ cw[i];
    if (s) return -1;
  }
  return L;
}

function correctBlocks(codewords, version, ecc) {
  const blocks = [];
  for (const [count, total, data] of RS_BLOCKS[ecc][version]) {
    for (let i = 0; i < count; i++) blocks.push({ total, data, cw: new Uint8Array(total) });
  }
  let maxData = 0;
  let maxEc = 0;
  for (const bl of blocks) {
    if (bl.data > maxData) maxData = bl.data;
    if (bl.total - bl.data > maxEc) maxEc = bl.total - bl.data;
  }
  let idx = 0;
  for (let i = 0; i < maxData; i++) {
    for (const bl of blocks) if (i < bl.data) bl.cw[i] = codewords[idx++];
  }
  for (let i = 0; i < maxEc; i++) {
    for (const bl of blocks) if (i < bl.total - bl.data) bl.cw[bl.data + i] = codewords[idx++];
  }
  const out = [];
  let fixed = 0;
  for (const bl of blocks) {
    const n = rsCorrect(bl.cw, bl.total - bl.data);
    if (n < 0) return null;
    fixed += n;
    for (let i = 0; i < bl.data; i++) out.push(bl.cw[i]);
  }
  return { data: Uint8Array.from(out), fixed };
}

// ------------------------------------------------------------ bit stream

const ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

function parseStream(data, version) {
  let pos = 0;
  const left = () => data.length * 8 - pos;
  const read = (n) => {
    let v = 0;
    for (let i = 0; i < n; i++) {
      v = (v << 1) | ((data[pos >> 3] >> (7 - (pos & 7))) & 1);
      pos++;
    }
    return v;
  };
  const chunks = [];
  const decoder = new TextDecoder("utf-8");
  while (left() >= 4) {
    const mode = read(4);
    if (mode === 0) break;
    if (mode === 7) {
      const first = read(8);
      if (first & 0x80) read(first & 0x40 ? 16 : 8);
      continue;
    }
    if (mode === 4) {
      const n = read(version < 10 ? 8 : 16);
      if (left() < n * 8) return null;
      const bytes = new Uint8Array(n);
      for (let i = 0; i < n; i++) bytes[i] = read(8);
      chunks.push(decoder.decode(bytes));
      continue;
    }
    if (mode === 1) {
      let n = read(version < 10 ? 10 : 12);
      let s = "";
      while (n >= 3) {
        if (left() < 10) return null;
        s += String(read(10)).padStart(3, "0");
        n -= 3;
      }
      if (n === 2) {
        if (left() < 7) return null;
        s += String(read(7)).padStart(2, "0");
      } else if (n === 1) {
        if (left() < 4) return null;
        s += String(read(4));
      }
      chunks.push(s);
      continue;
    }
    if (mode === 2) {
      let n = read(version < 10 ? 9 : 11);
      let s = "";
      while (n >= 2) {
        if (left() < 11) return null;
        const v = read(11);
        s += ALNUM[Math.floor(v / 45)] + ALNUM[v % 45];
        n -= 2;
      }
      if (n === 1) {
        if (left() < 6) return null;
        s += ALNUM[read(6)];
      }
      chunks.push(s);
      continue;
    }
    return null;
  }
  return chunks.join("");
}

// ---------------------------------------------------------------- decode

function decodeGrid(grid, dim, version) {
  const fmt = readFormat(grid, dim);
  if (!fmt) return null;
  let total = 0;
  for (const [count, size] of RS_BLOCKS[fmt.ecc][version]) total += count * size;
  const codewords = readCodewords(grid, dim, version, fmt.mask, total);
  if (!codewords) return null;
  const corrected = correctBlocks(codewords, version, fmt.ecc);
  if (!corrected) return null;
  const text = parseStream(corrected.data, version);
  if (text === null) return null;
  return { text, version, ecc: fmt.ecc, mask: fmt.mask, corrected: corrected.fixed };
}

function candidateDims(tri) {
  const { tl, tr, bl, ms } = tri;
  const est = (dist(tl, tr) + dist(tl, bl)) / 2 / ms + 7;
  const dims = [];
  for (let d = MIN_DIM; d <= MAX_DIM; d += 4) if (Math.abs(d - est) <= 6) dims.push(d);
  return dims.sort((a, b) => Math.abs(a - est) - Math.abs(b - est));
}

function tryDecode(bits, w, h, tri, dim, anchor) {
  const map = transformWith(tri, dim, anchor.point, anchor.pixel);
  if (!map) return null;
  const grid = sampleGrid(bits, w, h, map, dim);
  if (!grid) return null;
  const version = (dim - 17) / 4;
  if (version >= 7) {
    const v = readVersion(grid, dim);
    if (v !== null && v !== version) return null;
  }
  return decodeGrid(grid, dim, version);
}

// Offsets to walk the fourth corner through when nothing anchored it, in
// module units, nearest first. The cost is one sample-and-decode per step,
// and it only runs once three finders have been found and the direct
// attempts have failed.
const SEARCH = (() => {
  const out = [];
  for (let dy = -6; dy <= 6; dy++) for (let dx = -6; dx <= 6; dx++) if (dx || dy) out.push([dx / 2, dy / 2]);
  return out.sort((p, q) => Math.hypot(p[0], p[1]) - Math.hypot(q[0], q[1]));
})();

function decodeWithFinders(bits, w, h, tri) {
  const dims = candidateDims(tri);
  const ranked = [];
  for (const dim of dims) {
    for (const useAlignment of [true, false]) {
      const anchor = fourthAnchor(bits, w, h, tri, dim, useAlignment);
      if (!anchor) continue;
      const map = transformWith(tri, dim, anchor.point, anchor.pixel);
      if (!map) continue;
      const grid = sampleGrid(bits, w, h, map, dim);
      if (!grid) continue;
      ranked.push({ dim, anchor, score: timingScore(grid, dim) + (useAlignment ? 0.05 : 0) });
    }
  }
  ranked.sort((a, b) => b.score - a.score);
  for (const { dim, anchor } of ranked) {
    const out = tryDecode(bits, w, h, tri, dim, anchor);
    if (out) return out;
  }
  // Nothing decoded with the anchors as found: walk the free corner.
  const ms = Math.max(1, (tri.tr.ms * tri.bl.ms) / tri.tl.ms);
  for (const { dim, anchor } of ranked.slice(0, 2)) {
    const budget = dim <= 29 ? SEARCH.length : 60;
    for (const [dx, dy] of SEARCH.slice(0, budget)) {
      const moved = { point: anchor.point, pixel: [anchor.pixel[0] + dx * ms, anchor.pixel[1] + dy * ms] };
      const out = tryDecode(bits, w, h, tri, dim, moved);
      if (out) return out;
    }
  }
  return null;
}

// img is { data, width, height }: ImageData from a canvas, or a Uint8Array of
// width*height gray levels. Returns { text, version, ecc, mask } or null.
export function decode(img) {
  const gray = toGray(img);
  if (!gray) return null;
  const w = img.width | 0;
  const h = img.height | 0;
  if (w < MIN_DIM || h < MIN_DIM) return null;
  const bits = binarize(gray, w, h);
  const found = new Finders(bits, w, h).scan();
  const triples = orderTriples(found).slice(0, 6);
  for (const tri of triples) {
    const out = decodeWithFinders(bits, w, h, tri);
    if (out) return { text: out.text, version: out.version, ecc: out.ecc, mask: out.mask };
  }
  return null;
}
