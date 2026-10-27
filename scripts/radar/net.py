"""HTTP 小工具：只用 Python 內建 urllib，不需要安裝任何套件。"""
import json
import os
import time
import urllib.error
import urllib.request

UA = "sec-radar/1.0 (+https://github.com)"
FIXTURES = os.environ.get("RADAR_FIXTURES")  # 測試用：從本機檔案讀取，不連網


def _fixture(name):
    path = os.path.join(FIXTURES, name)
    with open(path, "rb") as f:
        return f.read()


def get(url, headers=None, fixture=None, timeout=40, tries=3):
    """GET 並回傳 bytes；失敗自動重試。測試模式下改讀 fixture 檔。"""
    if FIXTURES:
        if not fixture:
            raise RuntimeError(f"測試模式缺 fixture：{url}")
        return _fixture(fixture)
    h = {"User-Agent": UA}
    h.update(headers or {})
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 503):
                time.sleep(8 * (i + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
            time.sleep(4 * (i + 1))
    raise last


def get_json(url, headers=None, fixture=None, **kw):
    h = {"Accept": "application/json"}
    h.update(headers or {})
    return json.loads(get(url, headers=h, fixture=fixture, **kw).decode("utf-8"))


def post_json(url, payload, headers=None, timeout=60):
    h = {"Content-Type": "application/json", "User-Agent": UA}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))
