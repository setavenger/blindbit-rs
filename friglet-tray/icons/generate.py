#!/usr/bin/env python3
"""Resize friglet-tray icons from source.png (PNG set + ICO).

source.png is a Friglet variation of the BlindBit Desktop suite icon
(https://github.com/setavenger/blindbit-desktop — cmd/blindbit-desktop/icon.png),
produced with an AI image edit (orange accent ring + orange binary digits).

Requires Pillow. Run:

    python3 friglet-tray/icons/generate.py
"""

from __future__ import annotations

import io
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "source.png")

PNG_SIZES = {
    "32x32.png": 32,
    "128x128.png": 128,
    "128x128@2x.png": 256,
    "icon.png": 512,
}
ICO_SIZES = [16, 32, 48, 256]


def png_bytes(im) -> bytes:
    buf = io.BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def write_ico(images: list) -> bytes:
    """ICO with PNG-compressed entries (Vista+)."""
    pngs = [(im.size[0], png_bytes(im)) for im in images]
    header = struct.pack("<HHH", 0, 1, len(pngs))
    entries = b""
    offset = len(header) + 16 * len(pngs)
    for s, data in pngs:
        entries += struct.pack(
            "<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)
    return header + entries + b"".join(d for _, d in pngs)


def main() -> None:
    try:
        from PIL import Image
    except ImportError:
        print("need Pillow (`pip install pillow`)", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(SOURCE):
        print(f"missing {SOURCE}", file=sys.stderr)
        sys.exit(1)

    src = Image.open(SOURCE).convert("RGBA")
    for name, size in PNG_SIZES.items():
        out = os.path.join(HERE, name)
        src.resize((size, size), Image.Resampling.LANCZOS).save(out, optimize=True)
        print(f"wrote {name}")

    ico_imgs = [
        src.resize((s, s), Image.Resampling.LANCZOS) for s in ICO_SIZES
    ]
    with open(os.path.join(HERE, "icon.ico"), "wb") as f:
        f.write(write_ico(ico_imgs))
    print("wrote icon.ico")


if __name__ == "__main__":
    main()
