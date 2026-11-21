"""
Rebuild the Evasion mark with Pillow: python ui/build/generate_icons.py.

The mark is an E: a bracket of white and a middle bar that has slipped out of it,
violet at the tail and white at the head.
"""
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
SIZES = [16, 20, 24, 28, 32, 40, 48, 64, 128, 256]
CORE, HALO = (124, 108, 255), (84, 66, 255)


def bar(canvas, x0, x1, y, height):
    """Mask of one pill-shaped bar, in fractions of the canvas."""
    mask = Image.new("L", (canvas, canvas))
    half = height / 2
    ImageDraw.Draw(mask).rounded_rectangle(
        (x0 * canvas, (y - half) * canvas, x1 * canvas, (y + half) * canvas), radius=half * canvas, fill=255
    )
    return mask


def bracket(canvas, left, right, top, bottom, stroke, corner):
    """Mask of the E's spine with its two arms, round at the tips."""
    mask = Image.new("L", (canvas, canvas))
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle(
        (left * canvas, top * canvas, (right + corner + stroke) * canvas, bottom * canvas),
        radius=corner * canvas, outline=255, width=round(stroke * canvas),
    )
    draw.rectangle(((right - stroke / 2) * canvas, 0, canvas, canvas), fill=0)
    for y in (top, bottom - stroke):
        draw.ellipse(((right - stroke) * canvas, y * canvas, right * canvas, (y + stroke) * canvas), fill=255)
    return mask


def icon(size):
    """The E on a black tile; small sizes get heavier strokes and no glow detail."""
    scale = 4 if size >= 64 else 8
    canvas = size * scale
    small = size <= 32
    stroke = 0.14 if small else 0.1
    left, right, top, bottom, corner = (0.18, 0.62, 0.22, 0.78, 0.19) if small else (0.215, 0.61, 0.255, 0.745, 0.17)
    run = (0.47, 0.84) if small else (0.445, 0.805)

    # Tile: near-black with a violet floor glow.
    art = Image.new("RGB", (canvas, canvas), (5, 5, 7))
    if not small:
        wash = Image.new("RGB", (canvas, canvas))
        draw = ImageDraw.Draw(wash)
        draw.ellipse((0.34 * canvas, 0.62 * canvas, 1.2 * canvas, 1.3 * canvas), fill=(44, 30, 150))
        draw.ellipse((-0.3 * canvas, -0.4 * canvas, 0.5 * canvas, 0.2 * canvas), fill=(26, 24, 44))
        art = ImageChops.screen(art, wash.filter(ImageFilter.GaussianBlur(canvas * 0.13)))

    # The slipped bar fades from violet at its tail to white at its head.
    runner = bar(canvas, *run, 0.5, stroke)
    ramp = Image.new("RGB", (canvas, canvas))
    x0, x1 = round(run[0] * canvas), round(run[1] * canvas)
    px = ramp.load()
    for x in range(x0, x1):
        t = (x - x0) / max(1, x1 - x0 - 1)
        t = t * t * (3 - 2 * t)
        colour = tuple(round(a + (b - a) * t) for a, b in zip(CORE if small else HALO, (255, 255, 255)))
        for y in range(round((0.5 - stroke) * canvas), round((0.5 + stroke) * canvas)):
            px[x, y] = colour
    if not small:
        for tint, blur, power in ((HALO, 0.07, 0.95), (CORE, 0.022, 0.7)):
            glow = Image.new("RGB", (canvas, canvas))
            glow.paste(tuple(round(v * power) for v in tint), mask=runner)
            art = ImageChops.screen(art, glow.filter(ImageFilter.GaussianBlur(canvas * blur)))

    # The bracket runs from white at the top to a cool lavender at the foot.
    ink = Image.linear_gradient("L").resize((canvas, canvas))
    ink = Image.merge("RGB", [ink.point(lambda v, a=a, b=b: round(a + (b - a) * v / 255)) for a, b in zip((255, 255, 255), (208, 202, 255))])
    art.paste(ink, mask=bracket(canvas, left, right, top, bottom, stroke, corner))
    art.paste(ramp, mask=runner)

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
