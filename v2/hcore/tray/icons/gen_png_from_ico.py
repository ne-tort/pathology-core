#!/usr/bin/env python3
"""Generate PNG systray icons from ICO sources (Linux/macOS).

The ICO sources for `tray_icon`, `tray_icon_connected` and `tray_icon_dark` are
byte-identical, so "dark" used to mean "the same dark glyph". On a dark panel
(Ubuntu's top bar is #131313 by default) that glyph disappears and only its thin
white interior stays visible — which is why the tray looked empty.

This script also emits light variants (`*_light.png`) with inverted luminance
and an untouched alpha mask, so the glyph is drawn white on dark panels.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image

# ico source -> png outputs
SOURCES = {
    "tray_icon": ("tray_icon", "tray_icon_light"),
    "tray_icon_connected": ("tray_icon_connected", "tray_icon_connected_light"),
    "tray_icon_disconnected": ("tray_icon_disconnected", "tray_icon_disconnected_light"),
    "tray_icon_dark": ("tray_icon_dark",),
}
SIZE = 64


def light_variant(img: Image.Image) -> Image.Image:
    """White-on-transparent version of a dark glyph.

    Luminance is inverted (not flattened to solid white) so internal detail
    survives, and alpha is untouched so the silhouette stays identical.
    """
    src = img.convert("RGBA")
    out = Image.new("RGBA", src.size)
    sp = src.load()
    op = out.load()
    for y in range(src.size[1]):
        for x in range(src.size[0]):
            r, g, b, a = sp[x, y]
            lum = (r * 299 + g * 587 + b * 114) // 1000
            v = 255 - lum
            op[x, y] = (v, v, v, a)
    return out


def main() -> None:
    here = Path(__file__).resolve().parent
    for src_name, outputs in SOURCES.items():
        ico = here / f"{src_name}.ico"
        if not ico.is_file():
            raise SystemExit(f"missing {ico}")
        img = Image.open(ico).convert("RGBA").resize((SIZE, SIZE), Image.Resampling.LANCZOS)
        for out_name in outputs:
            png = here / f"{out_name}.png"
            target = light_variant(img) if out_name.endswith("_light") else img
            target.save(png, format="PNG")
            print(f"wrote {png.name} ({png.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
