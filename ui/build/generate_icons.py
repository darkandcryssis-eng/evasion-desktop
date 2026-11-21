"""Rebuild the ring identity with Pillow: python ui/build/generate_icons.py."""
from pathlib import Path
from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
SIZES = [16, 20, 24, 28, 32, 40, 48, 64, 128, 256]
INK, CORE, HALO = (241, 239, 255), (124, 108, 255), (84, 66, 255)


def ring_layer(canvas, radius, width, colour):
    layer = Image.new("RGB", (canvas, canvas))
    c = canvas / 2
    ImageDraw.Draw(layer).ellipse((c - radius, c - radius, c + radius, c + radius), outline=colour, width=max(1, round(width)))
    return layer


def icon(size):
    """A luminous ring with its centre dot on a black tile; small sizes get a heavier stroke."""
    scale = 4 if size >= 64 else 8
    canvas = size * scale
    small = size <= 32
    radius = canvas * (0.3 if small else 0.27)
    stroke = canvas * (0.075 if small else 0.027)
    dot = canvas * (0.08 if small else 0.044)
    power = 0.5 if small else 0.8
    c = canvas / 2

    art = Image.new("RGB", (canvas, canvas), (4, 4, 6))
    wash = Image.new("RGB", (canvas, canvas))
    ImageDraw.Draw(wash).ellipse((c - radius * 1.25, c - radius * 1.25, c + radius * 1.25, c + radius * 1.25), fill=(20, 13, 84) if not small else (0, 0, 0))
    art = ImageChops.screen(art, wash.filter(ImageFilter.GaussianBlur(canvas * 0.12)))
    ImageDraw.Draw(art).ellipse((c - radius, c - radius, c + radius, c + radius), fill=(13, 13, 20))
    for tint, grow, blur in ((HALO, 2.6, 0.05), (CORE, 1.5, 0.016)):
        colour = tuple(round(v * power) for v in tint)
        glow = ring_layer(canvas, radius + stroke * (grow - 1) / 2, stroke * grow, colour)
        ImageDraw.Draw(glow).ellipse((c - dot * 1.5, c - dot * 1.5, c + dot * 1.5, c + dot * 1.5), fill=colour)
        art = ImageChops.screen(art, glow.filter(ImageFilter.GaussianBlur(canvas * blur)))
    draw = ImageDraw.Draw(art)
    draw.ellipse((c - radius, c - radius, c + radius, c + radius), outline=INK, width=max(1, round(stroke)))
    draw.ellipse((c - dot, c - dot, c + dot, c + dot), fill=(255, 255, 255))

    mask = Image.new("L", (canvas, canvas))
    inset = canvas * 0.025
    ImageDraw.Draw(mask).rounded_rectangle((inset, inset, canvas - inset, canvas - inset), radius=canvas * 0.235, fill=255)
    art.putalpha(mask)
    return art.resize((size, size), Image.Resampling.LANCZOS)


if __name__ == "__main__":
    icon(512).save(ROOT / "build/appicon.png")
    images = [icon(size) for size in SIZES]
    for target in (ROOT / "assets/tray.ico", ROOT / "build/windows/icon.ico"):
        images[-1].save(target, format="ICO", sizes=[(s, s) for s in SIZES], append_images=images[:-1])
