"""Rebuild the cat identity with Pillow: python ui/build/generate_icons.py."""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
SIZES = [16, 20, 24, 28, 32, 40, 48, 64, 128, 256]


def icon(size):
    scale = size * 4 / 512
    image = Image.new("RGBA", (size * 4, size * 4))
    draw = ImageDraw.Draw(image)
    box = lambda values: tuple(round(v * scale) for v in values)
    draw.rounded_rectangle(box((12, 12, 500, 500)), radius=round(116 * scale), fill="#26262a")
    points = [(110, 270), (110, 120), (215, 183)]

    def curve(a, b, c, d):
        for step in range(1, 25):
            t = step / 24
            points.append(tuple((1-t)**3*a[i] + 3*(1-t)**2*t*b[i] + 3*(1-t)*t*t*c[i] + t**3*d[i] for i in (0, 1)))

    curve((215, 183), (242, 172), (270, 172), (297, 183))
    points += [(402, 120), (402, 270)]
    curve((402, 270), (402, 349), (342, 384), (256, 384))
    curve((256, 384), (170, 384), (110, 349), (110, 270))
    stroke = max(round(1.35 * 4), round(18 * scale))
    draw.line([box(p) for p in points], fill="#eeeef0", width=stroke, joint="curve")
    eye = max(9 * scale, 2.3)
    for x in (201, 311):
        x, y = x * scale, 266 * scale
        draw.ellipse((x-eye, y-eye, x+eye, y+eye), fill="#eeeef0")
    draw.line([box((241, 314)), box((256, 326)), box((271, 314))], fill="#eeeef0", width=max(4, round(12 * scale)), joint="curve")
    return image.resize((size, size), Image.Resampling.LANCZOS)


if __name__ == "__main__":
    icon(512).save(ROOT / "build/appicon.png")
    images = [icon(size) for size in SIZES]
    for target in (ROOT / "assets/tray.ico", ROOT / "build/windows/icon.ico"):
        images[-1].save(target, format="ICO", sizes=[(s, s) for s in SIZES], append_images=images[:-1])
