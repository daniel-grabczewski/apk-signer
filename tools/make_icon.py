"""Draw desktop/res/app.ico: a green rounded square with a white check mark.

Each size is drawn separately at 4x and scaled down, so the small sizes stay crisp.
Usage:  python tools/make_icon.py
"""

from pathlib import Path

from PIL import Image, ImageDraw

SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
TOP, BOTTOM = (46, 164, 79), (26, 127, 55)
OUT = Path(__file__).resolve().parent.parent / "desktop" / "res" / "app.ico"


def render(size):
    ss = 4
    w = size * ss
    pad = w * 0.06
    mask = Image.new("L", (w, w), 0)
    ImageDraw.Draw(mask).rounded_rectangle([pad, pad, w - pad, w - pad], radius=w * 0.22, fill=255)

    gradient = Image.new("RGBA", (w, w))
    px = gradient.load()
    for y in range(w):
        t = y / (w - 1)
        row = tuple(round(a + (b - a) * t) for a, b in zip(TOP, BOTTOM)) + (255,)
        for x in range(w):
            px[x, y] = row

    img = Image.new("RGBA", (w, w), (0, 0, 0, 0))
    img.paste(gradient, (0, 0), mask)

    # Thicker strokes at the small sizes so the tick survives the 16px taskbar icon.
    stroke = w * (0.13 if size <= 24 else 0.105)
    points = [(w * 0.28, w * 0.53), (w * 0.44, w * 0.685), (w * 0.73, w * 0.36)]
    draw = ImageDraw.Draw(img)
    draw.line(points, fill="white", width=round(stroke), joint="curve")
    r = stroke / 2
    for x, y in (points[0], points[-1]):
        draw.ellipse([x - r, y - r, x + r, y + r], fill="white")

    return img.resize((size, size), Image.LANCZOS)


def main():
    images = [render(s) for s in SIZES]
    images[-1].save(OUT, format="ICO", sizes=[(s, s) for s in SIZES], append_images=images[:-1])
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
