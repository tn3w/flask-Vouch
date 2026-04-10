import ipaddress
import logging
import threading
from bisect import bisect_right
from pathlib import Path
from urllib.request import urlopen

log = logging.getLogger("flask_vouch.blocklist")

BLOCKLIST_URL = (
    "https://github.com/tn3w/IPBlocklist/releases/latest/download/blocklist.txt"
)


def _parse_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        if "/" in line:
            net = ipaddress.ip_network(line, strict=False)
            return (
                net.version,
                int(net.network_address),
                int(net.broadcast_address),
            )
        if "-" in line:
            a, b = line.split("-", 1)
            start = ipaddress.ip_address(a.strip())
            end = ipaddress.ip_address(b.strip())
            return start.version, int(start), int(end)
        addr = ipaddress.ip_address(line)
        return addr.version, int(addr), int(addr)
    except ValueError:
        return None


def _merge(ranges):
    if not ranges:
        return []
    merged = [list(ranges[0])]
    for start, end in ranges[1:]:
        if start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _cache_path_for(source: str) -> Path | None:
    if not source.startswith(("http://", "https://")):
        return None
    filename = source.rstrip("/").rsplit("/", 1)[-1] or "blocklist.txt"
    return Path.home() / ".cache" / "tollbooth" / filename


def _load_text(source: str, cache: Path | None) -> str:
    if not source.startswith(("http://", "https://")):
        return Path(source).read_text()
    if cache and cache.exists():
        log.debug("Loading blocklist from cache: %s", cache)
        return cache.read_text()
    with urlopen(source) as resp:
        text = resp.read().decode()
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(text)
    return text


def parse_blocklist(text):
    v4, v6 = [], []
    for line in text.splitlines():
        result = _parse_line(line)
        if not result:
            continue
        version, start, end = result
        (v4 if version == 4 else v6).append((start, end))
    v4.sort()
    v6.sort()
    return _merge(v4), _merge(v6)


def _contains(starts, ends, val):
    idx = bisect_right(starts, val) - 1
    return idx >= 0 and val <= ends[idx]


class IPBlocklist:
    def __init__(self, source: str = BLOCKLIST_URL):
        self._source = source
        self._cache = _cache_path_for(source)
        self._v4_starts: list[int] = []
        self._v4_ends: list[int] = []
        self._v6_starts: list[int] = []
        self._v6_ends: list[int] = []

    @classmethod
    def from_sources(
        cls, sources: str | list[str]
    ) -> "IPBlocklist | list[IPBlocklist]":
        if isinstance(sources, str):
            return cls(sources)
        return [cls(s) for s in sources]

    def load(self, force: bool = False):
        cache = None if force else self._cache
        text = _load_text(self._source, cache)
        v4, v6 = parse_blocklist(text)
        s4, e4 = zip(*v4) if v4 else ([], [])
        s6, e6 = zip(*v6) if v6 else ([], [])
        self._v4_starts, self._v4_ends = list(s4), list(e4)
        self._v6_starts, self._v6_ends = list(s6), list(e6)

    def contains(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.version == 4:
            return _contains(self._v4_starts, self._v4_ends, int(addr))
        return _contains(self._v6_starts, self._v6_ends, int(addr))

    def start_updates(self, interval: int = 86400):
        def run():
            while True:
                threading.Event().wait(interval)
                try:
                    if self._cache and self._cache.exists():
                        self._cache.unlink()
                    self.load()
                    log.info("Blocklist updated: %d ranges", len(self))
                except Exception:
                    log.warning("Blocklist update failed", exc_info=True)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread

    def match_range(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        val = int(addr)
        if addr.version == 4:
            starts, ends = self._v4_starts, self._v4_ends
        else:
            starts, ends = self._v6_starts, self._v6_ends
        idx = bisect_right(starts, val) - 1
        if idx < 0 or val > ends[idx]:
            return None
        start_addr = ipaddress.ip_address(starts[idx])
        end_addr = ipaddress.ip_address(ends[idx])
        networks = list(ipaddress.summarize_address_range(start_addr, end_addr))
        if len(networks) == 1:
            return str(networks[0])
        return f"{start_addr}-{end_addr}"

    def __len__(self):
        return len(self._v4_starts) + len(self._v6_starts)
