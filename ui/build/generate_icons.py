"""Render the selected ev ligature from ui/assets/mark.svg.

    python -m pip install Pillow CairoSVG==2.7.1
    python ui/build/generate_icons.py

Keep the outline in mark.svg; the tile, tray mask and multi-resolution ICOs
are generated from that one source. No glow or state-dependent geometry.
"""
from io import BytesIO
from pathlib import Path
import re

import cairosvg
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SIZES = [16, 20, 24, 28, 32, 40, 48, 64, 128, 256]
MARK = (ROOT / "assets/mark.svg").read_text()
OUTLINE = re.search(r"<path\b[^>]+/>", MARK).group()
LOGO = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">\n'
    '  <rect width="256" height="256" rx="64" fill="#0d0d0f"/>\n'
    f'  {OUTLINE}\n</svg>\n'
)


def render(source, size):
    """Supersample each target, including every individual ICO resource."""
    data = cairosvg.svg2png(bytestring=source.encode(), output_width=size * 4, output_height=size * 4)
    return Image.open(BytesIO(data)).convert("RGBA").resize((size, size), Image.Resampling.LANCZOS)


if __name__ == "__main__":
    (ROOT / "assets/logo.svg").write_text(LOGO)
    render(MARK, 256).save(ROOT / "assets/mark.png")
    render(LOGO, 512).save(ROOT / "build/appicon.png")
    images = [render(LOGO, size) for size in SIZES]
    for target in (ROOT / "assets/tray.ico", ROOT / "build/windows/icon.ico"):
        images[-1].save(target, format="ICO", sizes=[(s, s) for s in SIZES], append_images=images[:-1])

    # GitHub sanitizes SVGs with external image references, so embed the outline.
    hero = ROOT.parent / "docs/readme/hero.svg"
    art = hero.read_text()
    art = re.sub(
        r"<!-- evasion-mark -->.*?<!-- /evasion-mark -->",
        f'<!-- evasion-mark -->\n      <g transform="scale(.1484375)">\n'
        f'        <rect width="256" height="256" rx="64" fill="#0d0d0f"/>\n'
        f'        {OUTLINE}\n      </g>\n      <!-- /evasion-mark -->',
        art, flags=re.S,
    )
    hero.write_text(art)
