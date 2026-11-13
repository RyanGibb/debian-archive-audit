"""Polite sequential HTTP fetcher for snapshot.debian.org.

One request at a time (global lock), a delay between requests, exponential
backoff on 429/5xx/network errors.  Returns bytes, or None on 404.
"""
import fcntl
import os
import threading
import time
import urllib.error
import urllib.request

BASE = "https://snapshot.debian.org/archive/debian/"
UA = "pdiff-replay-audit/1.0 (sequential, rate-limited)"

_lock = threading.Lock()
_last = [0.0]
STATS = {"requests": 0, "bytes": 0, "retries": 0, "404": 0}
DELAY = 0.15
MAX_WAIT = 4 * 3600  # give up after this long of continuous failure
# Cross-process lock so that parallel replay segments still make one request at a time.
LOCKFILE = os.environ.get("SNAPSCAN_LOCK")


class _XLock:
    def __enter__(self):
        _lock.acquire()
        self.fh = None
        if LOCKFILE:
            self.fh = open(LOCKFILE, "a+")
            fcntl.flock(self.fh, fcntl.LOCK_EX)
            self.fh.seek(0)
            try:
                _last[0] = max(_last[0], float(self.fh.read().strip() or 0))
            except ValueError:
                pass
        return self

    def __exit__(self, *a):
        if self.fh:
            self.fh.seek(0)
            self.fh.truncate()
            self.fh.write(repr(_last[0]))
            self.fh.flush()
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
        _lock.release()


class Down(Exception):
    pass


def get(url, log=None):
    waited = 0.0
    back = 5.0
    while True:
        with _XLock():
            gap = time.time() - _last[0]
            if gap < DELAY:
                time.sleep(DELAY - gap)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=180) as r:
                    data = r.read()
                _last[0] = time.time()
                STATS["requests"] += 1
                STATS["bytes"] += len(data)
                return data
            except urllib.error.HTTPError as e:
                _last[0] = time.time()
                STATS["requests"] += 1
                if e.code == 404:
                    STATS["404"] += 1
                    return None
                if e.code not in (429, 500, 502, 503, 504):
                    raise
                err = f"HTTP {e.code}"
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                _last[0] = time.time()
                err = repr(e)
        STATS["retries"] += 1
        if log:
            log(f"retry {url}: {err}; sleeping {back:.0f}s")
        if waited > MAX_WAIT:
            raise Down(f"{url}: {err} after {waited:.0f}s")
        time.sleep(back)
        waited += back
        back = min(back * 2, 1800)
