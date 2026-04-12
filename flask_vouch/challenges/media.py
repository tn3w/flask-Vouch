from concurrent.futures import ThreadPoolExecutor
from io import BytesIO


def distort_images(
    images: list[bytes],
    size: int = 100,
    hardness: int = 1,
) -> list[bytes]:
    with ThreadPoolExecutor(max_workers=len(images)) as pool:
        return list(pool.map(lambda img: distort_image(img, size, hardness), images))


def distort_image(image_data: bytes, size: int = 100, hardness: int = 1) -> bytes:
    try:
        import numpy as np
        from PIL import Image, ImageDraw, ImageFilter
    except ImportError as e:
        raise ImportError(
            "Pillow and numpy are required: pip install flask-vouch[image]"
        ) from e

    hardness = max(1, min(hardness, 5))
    rng = np.random.default_rng()

    img = Image.open(BytesIO(image_data)).convert("RGB")
    img = img.resize((size, size), Image.LANCZOS)
    arr = np.array(img, dtype=np.int16)

    noise_max = max(2, 1 + hardness // 2)
    arr = np.clip(arr + rng.integers(0, noise_max, arr.shape, dtype=np.int16), 0, 255)
    img = Image.fromarray(arr.astype(np.uint8))

    draw = ImageDraw.Draw(img)
    grid_size = max(8, 16 - hardness * 2)
    line_val = int(min(0.06 + hardness * 0.03, 0.18) * 2 * 255)
    color = (line_val, line_val, line_val)
    for i in range(0, size, grid_size):
        draw.line([(i, 0), (i, size)], fill=color, width=1)
        draw.line([(0, i), (size, i)], fill=color, width=1)

    num_lines = int(rng.integers(2 * hardness, 5 * hardness + 1))
    line_max = max(4, 3 * hardness)
    pts = rng.integers(0, size, (num_lines, 4))
    for pt1x, pt1y, pt2x, pt2y in pts:
        c = tuple(int(rng.integers(3, line_max)) for _ in range(3))
        draw.line([(int(pt1x), int(pt1y)), (int(pt2x), int(pt2y))], fill=c, width=1)

    arr = np.array(img, dtype=np.int16)
    num_dots = int(rng.integers(5 + 5 * hardness, 5 + 10 * hardness + 1))
    xs = rng.integers(0, size, num_dots)
    ys = rng.integers(0, size, num_dots)
    intensity = 0.05 + hardness * 0.05
    rand_max = max(2, 10 * hardness)
    deltas = rng.integers(0, rand_max, (num_dots, 3), dtype=np.int16)
    arr[ys, xs] = np.clip(
        (arr[ys, xs] * (1 - intensity)).astype(np.int16) + deltas, 0, 255
    )

    max_shift = hardness
    ys_idx, xs_idx = np.mgrid[0:size, 0:size]
    src_x = (xs_idx + rng.integers(-max_shift, max_shift + 1, (size, size))) % size
    src_y = (ys_idx + rng.integers(-max_shift, max_shift + 1, (size, size))) % size
    shifted = Image.fromarray(arr.astype(np.uint8)[src_y, src_x])
    shifted = shifted.filter(ImageFilter.GaussianBlur(hardness * 0.3))

    buf = BytesIO()
    shifted.save(buf, format="JPEG", quality=85)
    return buf.getvalue()
