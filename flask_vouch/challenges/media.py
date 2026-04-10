import secrets
from io import BytesIO


def distort_image(
    image_data: bytes,
    size: int = 100,
    hardness: int = 1,
) -> bytes:
    try:
        from PIL import Image, ImageDraw, ImageFilter
    except ImportError as e:
        raise ImportError("Pillow is required: pip install flask-bouncer[image]") from e

    hardness = max(1, min(hardness, 5))

    img = Image.open(BytesIO(image_data)).convert("RGB")
    img = img.resize((size, size), Image.LANCZOS)

    draw = ImageDraw.Draw(img)
    pixels = img.load()

    grid_size = max(8, 16 - hardness * 2)
    opacity_factor = min(0.06 + hardness * 0.03, 0.18)
    for i in range(0, size, grid_size):
        color = tuple(int(2 * opacity_factor * 255) for _ in range(3))
        draw.line([(i, 0), (i, size)], fill=color, width=1)
        draw.line([(0, i), (size, i)], fill=color, width=1)

    noise_max = max(1, 1 + hardness // 2)
    for y in range(size):
        for x in range(size):
            r, g, b = pixels[x, y]
            pixels[x, y] = (
                min(255, r + secrets.randbelow(noise_max)),
                min(255, g + secrets.randbelow(noise_max)),
                min(255, b + secrets.randbelow(noise_max)),
            )

    num_dots = secrets.randbelow(5 * hardness + 1) + 5 + 5 * hardness
    for _ in range(num_dots):
        x = secrets.randbelow(size)
        y = secrets.randbelow(size)
        rand_max = max(1, 10 * hardness)
        r, g, b = pixels[x, y]
        intensity = 0.05 + hardness * 0.05
        pixels[x, y] = (
            max(0, min(255, int(r * (1 - intensity) + secrets.randbelow(rand_max)))),
            max(0, min(255, int(g * (1 - intensity) + secrets.randbelow(rand_max)))),
            max(0, min(255, int(b * (1 - intensity) + secrets.randbelow(rand_max)))),
        )

    num_lines = secrets.randbelow(3 * hardness + 1) + 2 * hardness
    line_max = max(4, 3 * hardness)
    for _ in range(num_lines):
        pt1 = (secrets.randbelow(size), secrets.randbelow(size))
        pt2 = (secrets.randbelow(size), secrets.randbelow(size))
        color = tuple(secrets.randbelow(line_max - 2) + 3 for _ in range(3))
        draw.line([pt1, pt2], fill=color, width=1)

    max_shift = hardness
    shifted = Image.new("RGB", (size, size))
    src_pixels = img.load()
    dst_pixels = shifted.load()
    for y in range(size):
        for x in range(size):
            sx = (x + secrets.randbelow(2 * max_shift + 1) - max_shift) % size
            sy = (y + secrets.randbelow(2 * max_shift + 1) - max_shift) % size
            dst_pixels[x, y] = src_pixels[sx, sy]

    blur_radius = hardness * 0.3
    shifted = shifted.filter(ImageFilter.GaussianBlur(blur_radius))

    buf = BytesIO()
    shifted.save(buf, format="PNG")
    return buf.getvalue()
