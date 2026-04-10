import gzip
import json
import pickle
import secrets
import threading
from urllib.request import urlopen

_DATASET_URLS: dict[str, dict[str, str]] = {
    "image": {
        "keys": (
            "https://raw.githubusercontent.com/tn3w/"
            "Captcha_Datasets/refs/heads/master/"
            "datasets/keys.pkl"
        ),
        "animals": (
            "https://raw.githubusercontent.com/tn3w/"
            "Captcha_Datasets/refs/heads/master/"
            "datasets/animals.pkl"
        ),
        "ai_dogs": (
            "https://raw.githubusercontent.com/tn3w/"
            "Captcha_Datasets/refs/heads/master/"
            "datasets/ai-dogs.pkl"
        ),
    },
    "audio": {
        "characters": (
            "https://raw.githubusercontent.com/librecap/"
            "audiocaptcha/refs/heads/main/"
            "characters/characters.pkl"
        ),
    },
}

_LUA_RANDOM_IMAGES = """
local correct_key = KEYS[1]
local count = tonumber(ARGV[1])
local num_correct = tonumber(ARGV[2])
local num_incorrect = count - num_correct

local correct_len = tonumber(redis.call('LLEN', correct_key))
if correct_len == 0 then return nil end

local results = {}
local flags = {}
local preview_idx = math.random(0, correct_len - 1)
table.insert(results, redis.call('LINDEX', correct_key, preview_idx))

for i = 1, num_correct do
    local idx = math.random(0, correct_len - 1)
    table.insert(results, redis.call('LINDEX', correct_key, idx))
    table.insert(flags, '1')
end

local inc_keys = {}
for i = 2, #KEYS do
    table.insert(inc_keys, KEYS[i])
end

if #inc_keys > 0 then
    for i = 1, num_incorrect do
        local k = inc_keys[math.random(1, #inc_keys)]
        local l = tonumber(redis.call('LLEN', k))
        if l > 0 then
            local idx = math.random(0, l - 1)
            table.insert(results, redis.call('LINDEX', k, idx))
            table.insert(flags, '0')
        end
    end
end

local combined = {}
for i = 2, #results do
    table.insert(combined, {results[i], flags[i - 1]})
end

for i = #combined, 2, -1 do
    local j = math.random(1, i)
    combined[i], combined[j] = combined[j], combined[i]
end

local final = {results[1]}
local final_flags = {}
for _, pair in ipairs(combined) do
    table.insert(final, pair[1])
    table.insert(final_flags, pair[2])
end

table.insert(final, table.concat(final_flags, ''))
return final
"""

_LUA_RANDOM_AUDIO = """
local meta_key = KEYS[1]
local num_chars = tonumber(ARGV[1])
local lang = ARGV[2]

local all_chars = redis.call('SMEMBERS', meta_key)
if #all_chars == 0 then return nil end

local results = {}
local solution = {}
for i = 1, num_chars do
    local ch = all_chars[math.random(1, #all_chars)]
    table.insert(solution, ch)
    local audio = redis.call(
        'HGET', meta_key .. ':data', ch .. ':' .. lang
    )
    if audio then
        table.insert(results, audio)
    end
end

if #results ~= num_chars then return nil end
table.insert(results, table.concat(solution, ''))
return results
"""


class DatasetStore:
    def __init__(self, redis_client=None, prefix="tollbooth"):
        self._lock = threading.Lock()
        self._image: dict | None = None
        self._audio: dict | None = None
        self._r = redis_client
        self._prefix = prefix

        if self._r:
            self._img_script = self._r.register_script(
                _LUA_RANDOM_IMAGES,
            )
            self._audio_script = self._r.register_script(
                _LUA_RANDOM_AUDIO,
            )

    def _rkey(self, name: str) -> str:
        return f"{self._prefix}:ds:{name}"

    def _download(self, url: str) -> bytes:
        with urlopen(url, timeout=30) as resp:  # noqa: S310
            return resp.read()

    def _decompress_images(
        self,
        keys: dict[str, list[bytes]],
    ) -> dict[str, list[bytes]]:
        return {
            key: [gzip.decompress(img) for img in images]
            for key, images in keys.items()
        }

    def _store_images_redis(
        self,
        dataset: str,
        keys: dict[str, list[bytes]],
    ) -> None:
        meta_key = self._rkey(f"img:{dataset}:meta")
        pipe = self._r.pipeline(transaction=False)

        for category, images in keys.items():
            list_key = self._rkey(f"img:{dataset}:{category}")
            pipe.delete(list_key)
            for img in images:
                pipe.rpush(list_key, img)

        pipe.set(meta_key, json.dumps(list(keys.keys())))
        pipe.execute()

    def _store_audio_redis(
        self,
        dataset: str,
        keys: dict,
    ) -> None:
        chars_key = self._rkey(f"aud:{dataset}:chars")
        data_key = self._rkey(f"aud:{dataset}:chars:data")
        pipe = self._r.pipeline(transaction=False)
        pipe.delete(chars_key)
        pipe.delete(data_key)

        for char, langs in keys.items():
            pipe.sadd(chars_key, char)
            for lang, audio_bytes in langs.items():
                pipe.hset(data_key, f"{char}:{lang}", audio_bytes)

        pipe.execute()

    def _redis_has_images(self, dataset: str) -> bool:
        meta_key = self._rkey(f"img:{dataset}:meta")
        return bool(self._r.exists(meta_key))

    def _redis_has_audio(self, dataset: str) -> bool:
        chars_key = self._rkey(f"aud:{dataset}:chars")
        return self._r.scard(chars_key) > 0

    def load_image(self, dataset: str = "ai_dogs") -> bool:
        if self._r and self._redis_has_images(dataset):
            return True

        with self._lock:
            if self._image is not None:
                return True

        url = _DATASET_URLS["image"].get(dataset)
        if not url:
            return False

        raw = self._download(url)
        data = pickle.loads(raw)  # noqa: S301

        if data.get("type") != "image":
            return False

        keys = data.get("keys", {})
        if keys:
            data["keys"] = self._decompress_images(keys)

        if self._r and data.get("keys"):
            self._store_images_redis(dataset, data["keys"])
            return True

        with self._lock:
            self._image = data
        return True

    def load_audio(self, dataset: str = "characters") -> bool:
        if self._r and self._redis_has_audio(dataset):
            return True

        with self._lock:
            if self._audio is not None:
                return True

        url = _DATASET_URLS["audio"].get(dataset)
        if not url:
            return False

        raw = self._download(url)
        data = pickle.loads(raw)  # noqa: S301

        if self._r and data.get("keys"):
            self._store_audio_redis(dataset, data["keys"])
            return True

        with self._lock:
            self._audio = data
        return True

    def get_images(
        self,
        count: int = 9,
        correct_range: tuple[int, int] = (2, 3),
        dataset: str = "ai_dogs",
        preview: bool = False,
    ) -> tuple[list[bytes], str, str]:
        if not self.load_image(dataset):
            return [], "", ""

        if self._r:
            return self._get_images_redis(
                count,
                correct_range,
                dataset,
                preview,
            )

        return self._get_images_local(
            count,
            correct_range,
            preview,
        )

    def _get_images_redis(
        self,
        count: int,
        correct_range: tuple[int, int],
        dataset: str,
        preview: bool,
    ) -> tuple[list[bytes], str, str]:
        meta_key = self._rkey(f"img:{dataset}:meta")
        raw = self._r.get(meta_key)
        if not raw:
            return [], "", ""

        categories = json.loads(raw)
        if not categories:
            return [], "", ""

        correct_key = (
            categories[0] if len(categories) <= 2 else secrets.choice(categories)
        )

        num_correct = (
            secrets.randbelow(correct_range[1] - correct_range[0] + 1)
            + correct_range[0]
        )

        correct_list = self._rkey(
            f"img:{dataset}:{correct_key}",
        )
        incorrect_lists = [
            self._rkey(f"img:{dataset}:{c}") for c in categories if c != correct_key
        ]

        keys = [correct_list] + incorrect_lists
        result = self._img_script(
            keys=keys,
            args=[count, num_correct],
        )

        if not result:
            return [], "", ""

        flags_str = result[-1]
        if isinstance(flags_str, bytes):
            flags_str = flags_str.decode()

        all_images = [
            img if isinstance(img, bytes) else img.encode() for img in result[:-1]
        ]

        if preview:
            images = all_images
            correct_indices = flags_str
        else:
            images = all_images[1:]
            correct_indices = flags_str

        return images, correct_indices, correct_key

    def _get_images_local(
        self,
        count: int,
        correct_range: tuple[int, int],
        preview: bool,
    ) -> tuple[list[bytes], str, str]:
        with self._lock:
            data = self._image

        if not data or data.get("type") != "image":
            return [], "", ""

        keys = data.get("keys", {})
        if not keys:
            return [], "", ""

        key_names = list(keys.keys())
        correct_key = key_names[0] if len(key_names) <= 2 else secrets.choice(key_names)

        correct_pool = keys[correct_key]
        incorrect_pool = [
            img for k, imgs in keys.items() if k != correct_key for img in imgs
        ]
        if not correct_pool or not incorrect_pool:
            return [], "", ""

        num_correct = (
            secrets.randbelow(correct_range[1] - correct_range[0] + 1)
            + correct_range[0]
        )

        selected_correct = _sample(correct_pool, num_correct)
        remaining = count - len(selected_correct)
        selected_incorrect = _sample(incorrect_pool, remaining)

        combined = [(img, True) for img in selected_correct] + [
            (img, False) for img in selected_incorrect
        ]
        _shuffle(combined)

        images = [item[0] for item in combined]
        flags = [item[1] for item in combined]

        correct_indices = "".join(str(i) for i, flag in enumerate(flags) if flag)

        if preview:
            images = [secrets.choice(correct_pool)] + images

        return images, correct_indices, correct_key

    def get_audio(
        self,
        chars: int = 6,
        lang: str = "en",
        dataset: str = "characters",
    ) -> tuple[list[bytes], str]:
        if not self.load_audio(dataset):
            return [], ""

        if self._r:
            return self._get_audio_redis(chars, lang, dataset)

        return self._get_audio_local(chars, lang)

    def _get_audio_redis(
        self,
        chars: int,
        lang: str,
        dataset: str,
    ) -> tuple[list[bytes], str]:
        chars_key = self._rkey(f"aud:{dataset}:chars")
        result = self._audio_script(
            keys=[chars_key],
            args=[chars, lang],
        )

        if not result:
            return [], ""

        solution = result[-1]
        if isinstance(solution, bytes):
            solution = solution.decode()

        audio_files = [a if isinstance(a, bytes) else a.encode() for a in result[:-1]]

        return audio_files, solution

    def _get_audio_local(
        self,
        chars: int,
        lang: str,
    ) -> tuple[list[bytes], str]:
        with self._lock:
            data = self._audio

        if not data or data.get("type") != "audio":
            return [], ""

        keys = data.get("keys", {})
        if not keys:
            return [], ""

        available = list(keys.keys())
        selected = [secrets.choice(available) for _ in range(chars)]
        solution = "".join(selected)

        try:
            audio_files = [keys[ch][lang] for ch in selected]
            return audio_files, solution
        except KeyError:
            return [], ""


def _sample(pool: list, n: int) -> list:
    n = min(n, len(pool))
    indices = set()
    while len(indices) < n:
        indices.add(secrets.randbelow(len(pool)))
    return [pool[i] for i in indices]


def _shuffle(items: list) -> None:
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


_default_store = DatasetStore()


def get_default_store() -> DatasetStore:
    return _default_store


def set_default_store(store: DatasetStore) -> None:
    global _default_store
    _default_store = store
