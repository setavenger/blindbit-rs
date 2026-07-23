#!/usr/bin/env python3
"""Generate friglet-tray icons (PNG set + ICO) with no external deps.

Draws a flat silent-payment mark: bitcoin-orange coin with a white crescent
on a dark rounded square (eclipse / hidden-coin). Run:

    python3 friglet-tray/icons/generate.py
"""

import os
import struct
import zlib

BG = (27, 36, 50, 255)  # dark navy
COIN = (247, 147, 26, 255)  # bitcoin orange
MARK = (232, 238, 247, 255)  # near-white


def rounded_rect_mask(x, y, x0, y0, x1, y1, r):
    """1.0 if (x, y) is inside the rounded rect, else 0.0 (hard edge)."""
    if x < x0 or x > x1 or y < y0 or y > y1:
        return 0.0
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return 1.0 if (x - cx) ** 2 + (y - cy) ** 2 <= r * r else 0.0


def in_circle(x, y, cx, cy, r):
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def pixel(x, y, s):
    """RGBA for pixel (x, y) in an s-by-s icon."""
    # Background: rounded square with small transparent margin.
    m = s * 0.02
    if rounded_rect_mask(x, y, m, m, s - m, s - m, s * 0.22) == 0.0:
        return (0, 0, 0, 0)

    cx = cy = s * 0.5
    r = s * 0.30
    if not in_circle(x, y, cx, cy, r):
        return BG

    # White crescent on the right: inside coin, outside a left-shifted disk.
    crescent_cx = cx - r * 0.34
    if not in_circle(x, y, crescent_cx, cy, r * 0.92):
        return MARK

    return COIN


def render(s):
    rows = []
    for y in range(s):
        row = bytearray()
        for x in range(s):
            row.extend(pixel(x + 0.5, y + 0.5, s))
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
