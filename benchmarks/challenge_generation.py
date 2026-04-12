#!/usr/bin/env python3
"""Benchmark challenge generation time.

Usage:
    python benchmarks/challenge_generation.py                  # all, 10 iters
    python benchmarks/challenge_generation.py image            # single type
    python benchmarks/challenge_generation.py image_grid 50    # custom iters
"""

import sys
import time

from flask_vouch.challenges import (
    SHA256,
    CharacterCaptcha,
    CircleCaptcha,
    ImageCaptcha,
    ImageGridCaptcha,
    RotationCaptcha,
    SHA256Balloon,
    SlidingCaptcha,
)

HANDLERS = {
    "sha256": SHA256(),
    "sha256_balloon": SHA256Balloon(),
    "character": CharacterCaptcha(),
    "image": ImageCaptcha(),
    "rotation": RotationCaptcha(),
    "sliding": SlidingCaptcha(),
    "circle": CircleCaptcha(),
    "image_grid": ImageGridCaptcha(),
}

DIFFICULTY = 10


def benchmark(name: str, handler, iterations: int):
    difficulty = handler.to_difficulty(DIFFICULTY)
    start = time.perf_counter()
    for _ in range(iterations):
        handler.generate_random_data(difficulty)
    avg = (time.perf_counter() - start) / iterations
    print(f"{name}: {avg * 1000:.3f}ms avg over {iterations} iterations")


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    iterations = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    if target and target not in HANDLERS:
        print(f"Unknown type '{target}'. Options: {', '.join(HANDLERS)}")
        sys.exit(1)

    handlers = {target: HANDLERS[target]} if target else HANDLERS
    for name, handler in handlers.items():
        benchmark(name, handler, iterations)


if __name__ == "__main__":
    main()
