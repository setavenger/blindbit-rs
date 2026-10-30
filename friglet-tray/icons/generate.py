#!/usr/bin/env python3
"""Generate the friglet-tray icons (PNG set + ICO) with no external deps.

Friglet is a lightweight take on Frigate, Sparrow's Silent Payments Electrum
server, so the mark is a small sailing ship: two white sails over an orange
hull on a dark rounded square. Shapes are kept large so the glyph still reads
at tray size (16-32 px). Run from anywhere: python3 generate.py
"""

import os
import struct
import zlib

BG = (27, 36, 50, 255)  # dark navy
SAIL = (232, 238, 247, 255)  # near-white
ACCENT = (247, 147, 26, 255)  # bitcoin orange

# Shapes in unit coordinates (0..1, y pointing down), drawn back to front.
MAINSAIL = [(0.53, 0.16), (0.53, 0.63), (0.80, 0.63)]
JIB = [(0.48, 0.25), (0.48, 0.63), (0.24, 0.63)]
HULL = [(0.16, 0.68), (0.84, 0.68), (0.71, 0.81), (0.29, 0.81)]
SHAPES = [(MAINSAIL, SAIL), (JIB, SAIL), (HULL, ACCENT)]

SUPERSAMPLE = 4  # samples per pixel along each axis (anti-aliasing)


def in_rounded_rect(x, y, x0, y0, x1, y1, r):
    """True if (x, y) is inside the rounded rect."""
    if x < x0 or x > x1 or y < y0 or y > y1:
        return False
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_polygon(x, y, pts):
    """Even-odd ray-casting point-in-polygon test."""
    inside = False
    j = len(pts) - 1
    for i in range(len(pts)):
        xi, yi = pts[i]
        xj, yj = pts[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def sample(u, v):
    """RGBA at unit-space point (u, v)."""
    # Background: rounded square with a small transparent margin.
    if not in_rounded_rect(u, v, 0.02, 0.02, 0.98, 0.98, 0.22):
        return (0, 0, 0, 0)
    col = BG
    for pts, fill in SHAPES:
        if in_polygon(u, v, pts):
            col = fill
    return col


def pixel(x, y, s):
    """Anti-aliased RGBA for pixel (x, y) in an s-by-s icon."""
    n = SUPERSAMPLE
    acc = [0, 0, 0, 0]
    for j in range(n):
        for i in range(n):
            r, g, b, a = sample((x + (i + 0.5) / n) / s, (y + (j + 0.5) / n) / s)
            acc[0] += r * a
            acc[1] += g * a
            acc[2] += b * a
            acc[3] += a
    if acc[3] == 0:
        return (0, 0, 0, 0)
    # Average premultiplied colour, then un-premultiply.
    return (
        round(acc[0] / acc[3]),
        round(acc[1] / acc[3]),
        round(acc[2] / acc[3]),
        round(acc[3] / (n * n)),
    )


def render(s):
    rows = []
    for y in range(s):
        row = bytearray()
        for x in range(s):
            row.extend(pixel(x, y, s))
        rows.append(bytes(row))
    return rows


def png_bytes(s):
    rows = render(s)
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", s, s, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def ico_bytes(sizes):
    pngs = [(s, png_bytes(s)) for s in sizes]
    header = struct.pack("<HHH", 0, 1, len(pngs))
    entries = b""
    offset = len(header) + 16 * len(pngs)
    for s, data in pngs:
        entries += struct.pack(
            "<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)
    return header + entries + b"".join(d for _, d in pngs)


def main():
    out = os.path.dirname(os.path.abspath(__file__))
    files = {
        "32x32.png": 32,
        "128x128.png": 128,
        "128x128@2x.png": 256,
        "icon.png": 512,
    }
    for name, size in files.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(png_bytes(size))
        print(f"wrote {name}")
    with open(os.path.join(out, "icon.ico"), "wb") as f:
        f.write(ico_bytes([16, 32, 48, 256]))
    print("wrote icon.ico")


if __name__ == "__main__":
    main()
