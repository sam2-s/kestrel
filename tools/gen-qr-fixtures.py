#!/usr/bin/env python3
"""Render the QR fixtures test/qrscan.test.mjs decodes.

python qrcode is the ground truth for the module matrix, Pillow and numpy
warp the rendered image. Every image is written as an 8-bit PGM (P5) next
to a manifest.json that names the file, the text, the version, the mask,
the error correction level and the distortion class.

    python3 tools/gen-qr-fixtures.py OUT_DIR [--classes clean,rot90,...] [--seed N]
"""
import argparse
import json
import os
import random
import sys

import numpy as np
import qrcode
import qrcode.base
import qrcode.util
from PIL import Image, ImageFilter

LEVELS = {
    "L": qrcode.constants.ERROR_CORRECT_L,
    "M": qrcode.constants.ERROR_CORRECT_M,
    "Q": qrcode.constants.ERROR_CORRECT_Q,
    "H": qrcode.constants.ERROR_CORRECT_H,
}

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/-_. "

# What the safety number sheet actually encodes, at the version it lands in.
SAFETY = "starling:sn:1:5f1d2c3b4a5968778695a4b3c2d1e0ff:793209194800309342692516966015"


def capacity_bytes(version, level):
    bits = qrcode.util.BIT_LIMIT_TABLE[LEVELS[level]][version]
    return (bits - 4 - (8 if version < 10 else 16)) // 8


def text_for(version, level, rng):
    cap = capacity_bytes(version, level)
    if cap >= len(SAFETY) and level == "M" and version == 5:
        return SAFETY
    n = max(1, cap - rng.randint(0, min(3, cap - 1)))
    return "".join(rng.choice(ALPHABET) for _ in range(n))


def matrix(text, version, mask, level):
    qr = qrcode.QRCode(
        version=version,
        error_correction=LEVELS[level],
        box_size=1,
        border=0,
        mask_pattern=mask,
    )
    qr.add_data(qrcode.util.QRData(text.encode(), mode=qrcode.util.MODE_8BIT_BYTE), optimize=0)
    qr.make(fit=False)
    m = np.array(qr.modules, dtype=bool)
    assert m.shape == (version * 4 + 17, version * 4 + 17)
    return m


def correctable(version, level):
    # Codewords per block the decoder can fix, summed over blocks.
    return sum((b.total_count - b.data_count) // 2 for b in qrcode.base.rs_blocks(version, LEVELS[level]))


def finder_mask(n):
    f = np.zeros((n, n), dtype=bool)
    f[0:9, 0:9] = True
    f[0:9, n - 8:] = True
    f[n - 8:, 0:9] = True
    return f


def render(mods, scale, quiet=4):
    n = mods.shape[0]
    size = (n + 2 * quiet) * scale
    img = np.full((size, size), 255, dtype=np.uint8)
    dark = np.kron(mods, np.ones((scale, scale), dtype=bool))
    off = quiet * scale
    img[off:off + n * scale, off:off + n * scale][dark] = 0
    return img


def to_pil(arr):
    return Image.fromarray(arr, mode="L")


def perspective_coeffs(src, dst):
    rows = []
    for (x, y), (u, v) in zip(src, dst):
        rows.append([x, y, 1, 0, 0, 0, -u * x, -u * y])
        rows.append([0, 0, 0, x, y, 1, -v * x, -v * y])
    a = np.array(rows, dtype=float)
    b = np.array([c for p in dst for c in p], dtype=float)
    return np.linalg.solve(a, b)


def warp_perspective(img, rng):
    h, w = img.shape
    k = 0.12
    pad = int(0.15 * max(w, h))
    corners = [(0, 0), (w, 0), (w, h), (0, h)]
    moved = [(x + pad + rng.uniform(-k * w, k * w), y + pad + rng.uniform(-k * h, k * h)) for x, y in corners]
    # PIL maps OUTPUT pixels back to input, so the coefficients go moved -> corners.
    out = to_pil(img).transform((w + 2 * pad, h + 2 * pad), Image.PERSPECTIVE,
                                perspective_coeffs(moved, corners), resample=Image.BILINEAR, fillcolor=255)
    return np.array(out)


def write_pgm(path, arr):
    h, w = arr.shape
    with open(path, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (w, h))
        f.write(np.ascontiguousarray(arr).tobytes())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--classes", default="clean,rot90,rot180,rot270,rot15,persp,blur,noise,damage")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    classes = args.classes.split(",")
    os.makedirs(args.out, exist_ok=True)
    rng = random.Random(args.seed)
    nrng = np.random.default_rng(args.seed)
    manifest = []
    count = 0

    def emit(arr, cls, text, version, mask, level, scale, **extra):
        nonlocal count
        name = "%s-v%02d-m%d-%s-%04d.pgm" % (cls, version, mask, level, count)
        count += 1
        write_pgm(os.path.join(args.out, name), arr)
        manifest.append(dict(file=name, cls=cls, text=text, version=version, mask=mask,
                             level=level, scale=scale, width=int(arr.shape[1]),
                             height=int(arr.shape[0]), **extra))

    for version in range(1, 11):
        for mask in range(8):
            for level in "LMQH":
                text = text_for(version, level, rng)
                mods = matrix(text, version, mask, level)
                if "clean" in classes:
                    emit(render(mods, 3), "clean", text, version, mask, level, 3)
                if level != "M":
                    continue
                base3 = render(mods, 3)
                for k, cls in ((1, "rot90"), (2, "rot180"), (3, "rot270")):
                    if cls in classes:
                        emit(np.ascontiguousarray(np.rot90(base3, k)), cls, text, version, mask, level, 3)
                base4 = render(mods, 4)
                if "rot15" in classes:
                    angle = rng.choice([-17, -15, -13, 13, 15, 17])
                    rot = to_pil(base4).rotate(angle, resample=Image.BICUBIC, expand=True, fillcolor=255)
                    emit(np.array(rot), "rot15", text, version, mask, level, 4, angle=angle)
                if "persp" in classes:
                    emit(warp_perspective(base4, rng), "persp", text, version, mask, level, 4)
                if "blur" in classes:
                    radius = 1.4
                    blurred = to_pil(base4).filter(ImageFilter.GaussianBlur(radius))
                    emit(np.array(blurred), "blur", text, version, mask, level, 4, radius=radius)
                if "noise" in classes:
                    sigma = 32
                    noisy = np.clip(base4.astype(float) + nrng.normal(0, sigma, base4.shape), 0, 255)
                    emit(noisy.astype(np.uint8), "noise", text, version, mask, level, 4, sigma=sigma)
                if "damage" in classes:
                    n = mods.shape[0]
                    keep = finder_mask(n)
                    spots = [(r, c) for r in range(n) for c in range(n) if not keep[r, c]]
                    budget = correctable(version, level)
                    for frac in (0.25, 0.5, 1.0):
                        flips = max(1, int(round(budget * frac)))
                        hit = mods.copy()
                        for r, c in rng.sample(spots, flips):
                            hit[r, c] = not hit[r, c]
                        emit(render(hit, 3), "damage", text, version, mask, level, 3,
                             flips=flips, budget=budget, frac=frac)

    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f)
    print("%d fixtures" % len(manifest), file=sys.stderr)


if __name__ == "__main__":
    main()
