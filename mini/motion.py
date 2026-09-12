"""Motion attestation: scores a collected interaction session on movement alone."""

from __future__ import annotations

import math
from collections import Counter

MIN_INTERACTION_EVENTS = 12
POISON_RATIO = 0.8
POISONED_SCORE = 0.45
CONCLUSIVE_CATEGORIES = {"contract", "kinematics", "mouse", "dispatch"}

SAMPLE_SPACING_MS = 25
MIN_PATH_SAMPLES = 6
MIN_PATH_DISTANCE = 40
GESTURE_GAP_MS = 100

MOUSE_BANDS = {
    "end_ratio": (-1, 0, 0.25, 0.6),
    "high_frequency": (0.15, 0.3, 0.95, 1.35),
    "turn_mean": (0.03, 0.08, 0.7, 1.1),
    "fast_turn": (-1, 0, 0.3, 0.7),
    "efficiency": (-1, 0, 0.985, 1),
    "speed_cv": (0.15, 0.35, 2.6, 3.2),
}

TOUCH_BANDS = {
    "end_ratio": (-1, 0, 0.35, 0.7),
    "high_frequency": (0.5, 0.85, 1.9, 2.4),
    "turn_mean": (0.15, 0.3, 1, 1.35),
    "fast_turn": (0.15, 0.35, 2.1, 2.7),
    "efficiency": (0.01, 0.06, 0.9, 0.99),
    "speed_cv": (0.3, 0.6, 2.4, 3),
}

KINEMATIC_WEIGHTS = {
    "end_ratio": 0.075,
    "high_frequency": 0.075,
    "turn_mean": 0.055,
    "fast_turn": 0.04,
    "efficiency": 0.03,
    "speed_cv": 0.025,
}

KINEMATIC_LABELS = {
    "end_ratio": "no deceleration into the target",
    "high_frequency": "path micro-structure",
    "turn_mean": "turn distribution",
    "fast_turn": "turns while fast",
    "efficiency": "straight-line path",
    "speed_cv": "speed variation",
}

CORE_FEATURES = ("end_ratio", "high_frequency", "turn_mean")
CONTRADICTION_FIT = 0.35
MOUSE_PATH_PENALTY = 0.7
TOUCH_PATH_PENALTY = 0.3

LIMITS = {
    "m": (3, 600),
    "c": (6, 100),
    "k": (2, 200),
    "s": (3, 300),
    "tc": (6, 400),
    "ev": (2, 600),
}


def mean(values) -> float:
    return sum(values) / len(values) if values else 0.0


def stddev(values) -> float:
    if len(values) < 2:
        return 0.0
    average = mean(values)
    return math.sqrt(sum((value - average) ** 2 for value in values) / len(values))


def coefficient_of_variation(values) -> float:
    average = mean(values)
    return stddev(values) / abs(average) if average else 0.0


def shannon_entropy(values, bin_count: int) -> float:
    if len(values) < 2:
        return 0.0

    low, span = min(values), (max(values) - min(values)) or 1
    bins = [0] * bin_count
    for value in values:
        bins[min(int((value - low) / span * bin_count), bin_count - 1)] += 1

    shares = [count / len(values) for count in bins if count]
    return -sum(share * math.log2(share) for share in shares)


def distance(first_x, first_y, second_x, second_y) -> float:
    return math.hypot(second_x - first_x, second_y - first_y)


def count_decimals(value) -> int:
    if float(value).is_integer():
        return 0
    text = repr(float(value))
    return len(text) - text.index(".") - 1 if "." in text else 0


def fraction_non_integer(values) -> float:
    if not values:
        return 0.0
    return sum(1 for value in values if not float(value).is_integer()) / len(values)


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def band(value: float, limits) -> float:
    low_fail, low_pass, high_pass, high_fail = limits
    if not math.isfinite(value):
        return 0.0
    if low_pass <= value <= high_pass:
        return 1.0
    if value < low_pass:
        return clamp((value - low_fail) / (low_pass - low_fail))
    return clamp((high_fail - value) / (high_fail - high_pass))


def _is_number(value) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


def _rows(raw, width: int, limit: int) -> list:
    if not isinstance(raw, list):
        return []

    rows = []
    for entry in raw:
        if len(rows) >= limit:
            break
        if not isinstance(entry, list) or len(entry) < width:
            continue
        if all(map(_is_number, entry[:width])):
            rows.append([float(value) for value in entry[:width]])
    return rows


def _session(data) -> dict:
    if not isinstance(data, dict):
        data = {}

    return {key: _rows(data.get(key), *limits) for key, limits in LIMITS.items()}


class Category:
    def __init__(self, max_penalty: float):
        self.penalty = 0.0
        self.max_penalty = max_penalty
        self.reasons: list[str] = []

    def add(self, amount: float, reason: str) -> None:
        self.penalty += amount
        self.reasons.append(reason)

    def capped(self) -> "Category":
        self.penalty = min(self.penalty, self.max_penalty)
        return self


def analyze_evidence(session: dict) -> Category:
    """Missing interaction is never a pass: too few events costs most of the score."""
    category = Category(0.6)
    events = sum(len(session[key]) for key in ("m", "c", "k", "s", "tc"))
    if events >= MIN_INTERACTION_EVENTS:
        return category

    category.penalty = category.max_penalty * (1 - events / MIN_INTERACTION_EVENTS)
    category.reasons.append(f"Only {events} interaction events recorded")
    return category


def _is_monotonic(times) -> bool:
    return all(times[index] >= times[index - 1] for index in range(1, len(times)))


def analyze_contract(session: dict) -> Category:
    """Transcripts that are physically impossible, whatever else they look like."""
    category = Category(0.6)
    violations = []

    if not _is_monotonic([point[2] for point in session["m"]]):
        violations.append("Non-monotonic mouse clock")
    if not _is_monotonic([point[5] for point in session["tc"]]):
        violations.append("Non-monotonic touch clock")

    early_releases = len([key for key in session["k"] if key[0] < 0])
    if early_releases:
        violations.append(f"{early_releases} keystrokes released before pressed")

    if violations:
        category.penalty = category.max_penalty
        category.reasons.extend(violations)
    return category


def _path_features(points: list) -> dict:
    steps, intervals, turns = [], [], []
    for index in range(1, len(points)):
        delta_x = points[index][0] - points[index - 1][0]
        delta_y = points[index][1] - points[index - 1][1]
        steps.append(math.hypot(delta_x, delta_y))
        intervals.append(max(points[index][2] - points[index - 1][2], 1))
        if index > 1:
            before_x = points[index - 1][0] - points[index - 2][0]
            before_y = points[index - 1][1] - points[index - 2][1]
            cross = before_x * delta_y - before_y * delta_x
            dot = before_x * delta_x + before_y * delta_y
            turns.append(abs(math.atan2(cross, dot)))

    path_length = sum(steps)
    speeds = [step / intervals[index] for index, step in enumerate(steps)]
    peak = max(speeds)
    wobble = [
        math.hypot(
            points[index][0] - 2 * points[index - 1][0] + points[index - 2][0],
            points[index][1] - 2 * points[index - 1][1] + points[index - 2][1],
        )
        for index in range(2, len(points))
    ]
    fast_turns = [
        turn for index, turn in enumerate(turns) if speeds[index + 1] >= peak * 0.3
    ]

    return {
        "path_length": path_length,
        "efficiency": distance(points[0][0], points[0][1], points[-1][0], points[-1][1])
        / (path_length or 1),
        "turn_mean": mean(turns),
        "fast_turn": mean(fast_turns),
        "high_frequency": mean(wobble) / (mean(steps) or 1),
        "end_ratio": speeds[-1] / peak if peak else 1.0,
        "speed_cv": coefficient_of_variation(speeds),
    }


def _path_fit(points: list, bands: dict, label: str, category: Category):
    if len(points) < MIN_PATH_SAMPLES:
        return None

    features = _path_features(points)
    if features["path_length"] < MIN_PATH_DISTANCE:
        return None

    fits = {}
    weighted = 0.0
    for feature, weight in KINEMATIC_WEIGHTS.items():
        fits[feature] = band(features[feature], bands[feature])
        weighted += fits[feature] * weight
        if fits[feature] < 0.5:
            category.reasons.append(
                f"{label}: {KINEMATIC_LABELS[feature]} "
                f"({features[feature]:.2f}, fit={fits[feature]:.2f})"
            )

    core = min(fits[feature] for feature in CORE_FEATURES)
    return (weighted / sum(KINEMATIC_WEIGHTS.values())) * clamp(0.3 + 0.7 * core)


def _resample(points: list) -> list:
    kept: list = []
    for point in points:
        if not kept or point[2] - kept[-1][2] >= SAMPLE_SPACING_MS:
            kept.append(point)
    return kept


def _gestures(points: list) -> list:
    groups: list = []
    current: list = []
    for point in points:
        if current and point[2] - current[-1][2] > GESTURE_GAP_MS:
            groups.append(current)
            current = []
        current.append(point)
    if current:
        groups.append(current)
    return groups


def _best_fit(groups: list, bands: dict, label: str, category: Category):
    fits = []
    for group in groups:
        spaced = _resample(group)
        fit = _path_fit(
            spaced if len(spaced) >= MIN_PATH_SAMPLES else group, bands, label, category
        )
        if fit is not None:
            fits.append(fit)
    return max(fits) if fits else None


def analyze_kinematics(session: dict) -> Category:
    """Six band-measured path features; the best-fitting path carries the session."""
    category = Category(MOUSE_PATH_PENALTY)
    touch_path = [[point[0], point[1], point[5]] for point in session["tc"]]
    channels = [
        (_best_fit([session["m"]], MOUSE_BANDS, "mouse", category), MOUSE_PATH_PENALTY),
        (
            _best_fit(_gestures(touch_path), TOUCH_BANDS, "touch", category),
            TOUCH_PATH_PENALTY,
        ),
    ]
    channels = [(fit, weight) for fit, weight in channels if fit is not None]
    if not channels:
        return category

    penalty = min(weight * (1 - fit) for fit, weight in channels)
    if len(channels) > 1 and min(fit for fit, _ in channels) < CONTRADICTION_FIT:
        penalty += 0.08
        category.reasons.append("A second input channel contradicts the first")

    category.penalty = penalty
    return category.capped()


def _check_curvature(points: list, category: Category) -> None:
    curvatures = []
    for index in range(1, len(points) - 1):
        first, middle, last = points[index - 1], points[index], points[index + 1]
        side_a = distance(first[0], first[1], middle[0], middle[1])
        side_b = distance(middle[0], middle[1], last[0], last[1])
        side_c = distance(last[0], last[1], first[0], first[1])
        if side_a and side_b and side_c:
            cross = abs(
                (middle[0] - first[0]) * (last[1] - first[1])
                - (middle[1] - first[1]) * (last[0] - first[0])
            )
            curvatures.append(2 * cross / (side_a * side_b * side_c))

    if len(curvatures) < 10:
        return

    entropy = shannon_entropy(curvatures, 15)
    if entropy < 1.0:
        category.add(0.12, f"Low curvature entropy: {entropy:.2f} (straight-line)")
    elif entropy < 1.8:
        category.add(0.05, f"Below-average curvature entropy: {entropy:.2f}")


def _check_tremor(points: list, category: Category) -> None:
    if len(points) < 10:
        return

    residuals = []
    for index in range(2, len(points) - 2):
        window = points[index - 2 : index + 3]
        smooth_x = sum(point[0] for point in window) / 5
        smooth_y = sum(point[1] for point in window) / 5
        residuals.append(
            distance(points[index][0], points[index][1], smooth_x, smooth_y)
        )

    tremor = math.sqrt(mean([value * value for value in residuals]))
    if tremor < 0.05:
        category.add(0.1, f"No micro-tremor: RMS={tremor:.3f}px (too smooth)")
    elif tremor > 60:
        category.add(0.06, f"Excessive tremor: RMS={tremor:.1f}px (noise injection?)")


def _check_velocity(points: list, category: Category) -> None:
    velocities = []
    for index in range(1, len(points)):
        elapsed = points[index][2] - points[index - 1][2]
        if elapsed > 0:
            before, current = points[index - 1], points[index]
            step = distance(before[0], before[1], current[0], current[1])
            velocities.append(step / elapsed)

    if len(velocities) < 10:
        return

    variation = coefficient_of_variation(velocities)
    if variation < 0.15:
        category.add(0.12, f"Constant velocity: CV={variation:.3f}")
    elif variation < 0.3:
        category.add(0.05, f"Low velocity variance: CV={variation:.3f}")


def _check_straightness(points: list, category: Category) -> None:
    if len(points) < 20:
        return

    ratios = []
    for start in range(0, len(points) - 14, 5):
        segment = points[start : start + 15]
        direct = distance(segment[0][0], segment[0][1], segment[-1][0], segment[-1][1])
        if direct < 5:
            continue
        length = sum(
            distance(segment[i - 1][0], segment[i - 1][1], segment[i][0], segment[i][1])
            for i in range(1, len(segment))
        )
        ratios.append(length / direct)

    if len(ratios) < 3:
        return

    average = mean(ratios)
    if average < 1.005:
        category.add(0.1, f"Perfectly straight paths: index={average:.4f}")
    elif average < 1.015:
        category.add(0.04, f"Very straight paths: index={average:.4f}")


def _check_constant_acceleration(points: list, category: Category) -> None:
    if len(points) < 20:
        return

    smooth = 0
    for index in range(3, len(points)):
        before_x = (
            points[index - 1][0] - 2 * points[index - 2][0] + points[index - 3][0]
        )
        before_y = (
            points[index - 1][1] - 2 * points[index - 2][1] + points[index - 3][1]
        )
        after_x = points[index][0] - 2 * points[index - 1][0] + points[index - 2][0]
        after_y = points[index][1] - 2 * points[index - 1][1] + points[index - 2][1]
        if math.hypot(after_x - before_x, after_y - before_y) < 1.5:
            smooth += 1

    share = smooth / (len(points) - 3)
    if share > 0.85:
        category.add(
            0.1, f"Curve-generated path: {share * 100:.0f}% constant acceleration"
        )


def _check_teleports(points: list, category: Category) -> None:
    teleports = 0
    for index in range(1, len(points)):
        step = distance(
            points[index - 1][0],
            points[index - 1][1],
            points[index][0],
            points[index][1],
        )
        if step > 300 and points[index][2] - points[index - 1][2] < 10:
            teleports += 1

    if teleports:
        category.add(
            min(0.15, teleports * 0.08), f"Pointer teleportation: {teleports} jumps"
        )

    at_origin = len([point for point in points if point[0] < 2 and point[1] < 2])
    if at_origin >= 2:
        category.add(0.08, f"{at_origin} points at the origin")


def _check_precision(points: list, category: Category) -> None:
    if len(points) >= 10 and fraction_non_integer([point[2] for point in points]) > 0.5:
        category.add(0.1, "Fractional pointer timestamps")

    precision = mean(
        [max(count_decimals(point[0]), count_decimals(point[1])) for point in points]
    )
    if precision > 6:
        category.add(0.15, f"Synthetic coordinate precision: {precision:.1f} decimals")
    elif precision > 3:
        category.add(0.08, f"Unusual coordinate precision: {precision:.1f} decimals")


def _check_event_clock(points: list, category: Category) -> None:
    """Real pointer events arrive on a device clock, so a few gaps dominate."""
    intervals = [
        round(points[index][2] - points[index - 1][2])
        for index in range(1, len(points))
    ]
    if len(intervals) < 20:
        return

    common = sum(count for _, count in Counter(intervals).most_common(3))
    share = common / len(intervals)
    if share < 0.45:
        category.add(
            0.12, f"Unquantized event clock: top gaps cover {share * 100:.0f}%"
        )
    elif share < 0.6:
        category.add(
            0.06, f"Weakly quantized event clock: top gaps cover {share * 100:.0f}%"
        )


def analyze_mouse(session: dict) -> Category:
    """Texture of the pointer trace: what a hand leaves behind and a curve does not."""
    category = Category(0.35)
    points = session["m"]
    if len(points) < 5:
        category.penalty = 0.2
        category.reasons.append("Insufficient pointer data")
        return category

    _check_curvature(points, category)
    _check_tremor(points, category)
    _check_velocity(points, category)
    _check_straightness(points, category)
    _check_constant_acceleration(points, category)
    _check_teleports(points, category)
    _check_precision(points, category)
    _check_event_clock(points, category)
    return category.capped()


def _check_click_placement(clicks: list, category: Category) -> None:
    offsets = [
        math.hypot(offset_x / (width / 2), offset_y / (height / 2))
        for offset_x, offset_y, _, width, height, _ in clicks
        if width > 0 and height > 0
    ]
    if len(offsets) < 3:
        return

    centered = len([value for value in offsets if value < 0.05]) / len(offsets)
    if centered > 0.7:
        category.add(0.12, f"{centered * 100:.0f}% pixel-perfect center clicks")
    elif centered > 0.5:
        category.add(0.06, f"{centered * 100:.0f}% center clicks")

    if len(offsets) >= 5 and stddev(offsets) < 0.02:
        category.add(0.08, "Click placement never varies")


def _check_click_timing(clicks: list, category: Category) -> None:
    dwells = [click[2] for click in clicks if click[2] >= 0]
    if not dwells:
        return

    zero_dwells = len([value for value in dwells if value == 0])
    if zero_dwells:
        category.add(0.15, f"{zero_dwells} zero-duration clicks (dispatched events)")
    elif mean(dwells) < 10:
        category.add(0.12, f"Impossibly fast clicks: {mean(dwells):.0f}ms")
    elif len(dwells) >= 5 and coefficient_of_variation(dwells) < 0.05:
        category.add(0.06, "Click duration never varies")

    if len(dwells) >= 3 and fraction_non_integer(dwells) > 0.5:
        category.add(0.08, "Fractional click timings")


def _check_keystrokes(keys: list, category: Category) -> None:
    if len(keys) < 3:
        return

    dwells = [key[0] for key in keys if key[0] > 0]
    flights = [key[1] for key in keys if key[1] >= 0]
    if len(dwells) >= 3 and mean(dwells) < 5:
        category.add(0.12, f"Key dwell impossibly short: {mean(dwells):.1f}ms")
    elif len(dwells) >= 3 and coefficient_of_variation(dwells) < 0.08:
        category.add(0.1, "Uniform key dwell (robotic)")

    too_fast = len([value for value in flights if 0 < value < 15])
    if flights and too_fast > len(flights) * 0.3:
        category.add(0.1, f"{too_fast} impossibly fast key transitions")


def _check_dispatch_pairs(events: list, category: Category) -> None:
    """A real press has time between mousedown and mouseup; a dispatched one does not."""
    instant = sum(
        1
        for index in range(1, len(events))
        if events[index - 1][0] == 1
        and events[index][0] == 2
        and events[index][1] == events[index - 1][1]
    )
    if instant:
        category.add(
            min(0.15, 0.08 * instant), f"{instant} zero-time press/release pairs"
        )

    presses = len([event for event in events if event[0] == 1])
    clicks = len([event for event in events if event[0] == 3])
    if clicks > presses:
        category.add(0.1, f"{clicks - presses} clicks without a press")


def analyze_dispatch(session: dict) -> Category:
    """Clicks and keystrokes an automation framework injects rather than performs."""
    category = Category(0.3)
    _check_click_placement(session["c"], category)
    _check_click_timing(session["c"], category)
    _check_keystrokes(session["k"], category)
    if len(session["ev"]) >= 5:
        _check_dispatch_pairs(session["ev"], category)
    return category.capped()


ANALYZERS = {
    "evidence": analyze_evidence,
    "contract": analyze_contract,
    "kinematics": analyze_kinematics,
    "mouse": analyze_mouse,
    "dispatch": analyze_dispatch,
}


def classify_score(score: float) -> str:
    if score >= 0.5:
        return "human"
    if score >= 0.3:
        return "suspicious"
    return "bot"


def score_motion(data) -> dict:
    """Score one interaction session, 1.0 reads as human."""
    session = _session(data)
    categories = {name: analyze(session) for name, analyze in ANALYZERS.items()}

    penalty = sum(category.penalty for category in categories.values())
    reasons = [
        f"[{name}] {reason}"
        for name, category in categories.items()
        for reason in category.reasons
    ]
    score = clamp(1.0 - penalty)

    conclusive = next(
        (
            name
            for name, category in categories.items()
            if name in CONCLUSIVE_CATEGORIES
            and category.penalty >= category.max_penalty * POISON_RATIO
        ),
        None,
    )
    if conclusive:
        score = min(score, POISONED_SCORE)
        reasons.append(f"[{conclusive}] channel is conclusively synthetic")

    return {
        "score": round(score, 3),
        "penalty": round(penalty, 3),
        "verdict": classify_score(score),
        "reasons": reasons,
    }
