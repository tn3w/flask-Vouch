const MOTION_LIMITS = { m: 500, c: 50, k: 100, s: 200, tc: 300, ev: 400 };

/**
 * Records pointer paths, clicks, key timings, scrolling and touch contacts.
 * Key identity is never stored, only how long each press lasted.
 */
function createMotionCollector() {
    const data = { m: [], c: [], k: [], s: [], tc: [], ev: [] };
    const origin = Date.now();
    const keyDown = new Map();
    let pressedAt = 0;
    let lastKeyUp = 0;

    const elapsed = () => Date.now() - origin;

    const record = (key, entry) => {
        if (data[key].length < MOTION_LIMITS[key]) data[key].push(entry);
    };

    function recordTouch(event) {
        for (const touch of event.changedTouches) {
            record('tc', [
                touch.clientX,
                touch.clientY,
                touch.force || 0,
                touch.radiusX || 0,
                touch.radiusY || 0,
                elapsed(),
            ]);
        }
    }

    const listeners = {
        mousemove(event) {
            record('m', [
                event.clientX + event.movementX * 0.01,
                event.clientY + event.movementY * 0.01,
                elapsed(),
            ]);
        },
        mousedown() {
            pressedAt = elapsed();
            record('ev', [1, pressedAt]);
        },
        mouseup() {
            record('ev', [2, elapsed()]);
        },
        click(event) {
            const now = elapsed();
            record('ev', [3, now]);
            const box = event.target ? event.target.getBoundingClientRect() : null;
            const dwell = pressedAt ? now - pressedAt : 0;
            pressedAt = 0;
            if (!box || !box.width || !box.height) {
                return record('c', [0, 0, dwell, 0, 0, now]);
            }
            record('c', [
                event.clientX - (box.left + box.width / 2),
                event.clientY - (box.top + box.height / 2),
                dwell,
                box.width,
                box.height,
                now,
            ]);
        },
        keydown(event) {
            if (!keyDown.has(event.code)) keyDown.set(event.code, elapsed());
        },
        keyup(event) {
            const down = keyDown.get(event.code);
            const now = elapsed();
            if (down !== undefined) {
                record('k', [now - down, lastKeyUp ? down - lastKeyUp : 0]);
            }
            lastKeyUp = now;
            keyDown.delete(event.code);
        },
        scroll() {
            const previous = data.s.length ? data.s[data.s.length - 1][0] : 0;
            record('s', [window.scrollY, window.scrollY - previous, elapsed()]);
        },
        touchstart(event) {
            recordTouch(event);
        },
        touchmove(event) {
            recordTouch(event);
        },
        touchend(event) {
            recordTouch(event);
        },
    };

    const options = { passive: true, capture: true };

    for (const type in listeners) {
        const target = type === 'scroll' ? window : document;
        target.addEventListener(type, listeners[type], options);
    }

    function detach() {
        for (const type in listeners) {
            const target = type === 'scroll' ? window : document;
            target.removeEventListener(type, listeners[type], { capture: true });
        }
    }

    function ready(minimumMs) {
        if (elapsed() < minimumMs) return false;
        return data.m.length >= 10 || data.tc.length >= 5 || data.k.length >= 3 ||
            data.s.length >= 3;
    }

    return { data, detach, ready, elapsed };
}
