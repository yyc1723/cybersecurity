"""Gemini AI 中文摘要。沒有金鑰或額度用完時，自動改用規則式摘要，網站照常更新。"""
import json
import os
import re
import time
import urllib.error

from . import config
from .net import post_json

API = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

RULES = """你是台灣企業資安中心的分析師，替同事撰寫資安警訊卡片。
規則：
- 使用台灣繁體中文與台灣慣用 IT 術語（例：遠端執行程式碼、權限提升、修補、伺服器）。
- 只能使用「輸入資料」裡的事實；版本號、數字、日期、是否遭利用，輸入沒寫就不要寫，絕不推測或編造。
- 產品名、CVE 編號、版本號保留原文。
- 語氣平實精簡，不加驚嘆號，不用「值得注意」「總之」這類贅詞。
- 全文最關鍵的一句風險或行動，用 **兩個星號** 包起來，整張卡最多一處。"""

EVENT_TASK = """以下是多則資安事件（JSON 陣列，每則有 id）。請逐則改寫成中文卡片，輸出 JSON：
{"items": [{"id": "...", "title": "...", "points": ["...", "..."], "fix": "..."}]}
- 每則輸入都要有一筆輸出，id 照抄。
- title：15 字以內的中文標題，點出產品與漏洞類型（例：「PHP 核心遠端執行漏洞」）。
- points：2 點，每點 70 字以內，英文內容要翻譯成中文：
  1. 影響什麼產品／版本、漏洞造成什麼後果
  2. 目前狀況（是否已遭利用、利用條件、範圍）
- fix：修補方式，80 字以內。只寫輸入明確提到的修補版本、更新名稱或緩解措施（例：「升級至 8.5.12、8.4.27 以上；暫時以 WAF 阻擋可疑請求」）。
  輸入只有「依原廠指示套用緩解措施」這類通用說明時，寫「依原廠公告套用修補或緩解措施，無法修補時停用該產品」。
  完全沒有修補資訊就輸出 ""，不要自己編。
- 類型為 news（新聞）時，points 改為 1～2 點新聞重點，fix 輸出 ""。
- **兩個星號** 的強調，每則最多一處。
事件：
"""

TODO_TASK = """以下是近幾天的緊急與高風險資安事件。請替同事整理「本日應辦事項」，輸出 JSON：
{"items": [{"title": "...", "desc": "..."}]}
- 最多 6 項，依急迫性排序；同類事件可合併成一項（例如多個語言執行環境更新合併成一項）。
- 「本單位產品」相關的事項排最前面，標題可加「本單位：」前綴。
- title 20 字以內，以動詞開頭（例：「升級 PHP 至修補版本」）；desc 40 字以內，說明原因或期限。
- 只能根據輸入內容，不要加入輸入沒有的事件。
本單位產品：{mine}
事件：
"""


class AI:
    def __init__(self):
        self.key = os.environ.get("GEMINI_API_KEY", "").strip()
        self.model = os.environ.get("GEMINI_MODEL", "").strip() or config.GEMINI_MODEL
        self.calls = 0
        self.disabled = not self.key
        self.last = 0.0

    @property
    def available(self):
        return not self.disabled and self.calls < config.AI_MAX_CALLS

    def _ask(self, prompt):
        wait = config.AI_GAP_SECONDS - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": RULES}]},
            "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
        }
        for attempt in range(2):
            try:
                self.calls += 1
                self.last = time.time()
                res = post_json(API.format(model=self.model), payload, headers={"x-goog-api-key": self.key})
                text = res["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(text)
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt == 0:
                    time.sleep(30)
                    continue
                if e.code in (400, 401, 403, 404):
                    print(f"[AI] 停用：HTTP {e.code}（請檢查 GEMINI_API_KEY 或 GEMINI_MODEL）")
                    self.disabled = True
                print(f"[AI] 呼叫失敗：HTTP {e.code}")
                return None
            except Exception as e:  # 回傳格式異常、逾時等
                print(f"[AI] 呼叫失敗：{type(e).__name__}")
                return None
        return None

    def summarize_batch(self, items):
        """items: [(id, context)]，一次送多則以節省額度。回傳 {id: {title, pts, fix}}。"""
        if not self.available or not items:
            return {}
        payload = [dict(id=i, **ctx) for i, ctx in items]
        out = self._ask(EVENT_TASK + json.dumps(payload, ensure_ascii=False, default=str))
        res = {}
        for it in (out or {}).get("items", []) if isinstance(out, dict) else []:
            if not isinstance(it, dict) or not isinstance(it.get("points"), list):
                continue
            pts = [clean(p, 140) for p in it["points"][:3] if isinstance(p, str) and p.strip()]
            title = clean(it.get("title") or "", 40)
            fix = clean(it.get("fix") or "", 160) if isinstance(it.get("fix"), str) else ""
            if pts and title and it.get("id") is not None:
                res[str(it["id"])] = dict(title=title, pts=pts, fix=fix)
        return res

    def todo(self, events, mine):
        if not self.available or not events:
            return None
        prompt = TODO_TASK.replace("{mine}", "、".join(mine)) + json.dumps(events, ensure_ascii=False)
        out = self._ask(prompt)
        items = (out or {}).get("items")
        if not isinstance(items, list):
            return None
        res = [dict(title=clean(i.get("title", ""), 30), desc=clean(i.get("desc", ""), 70))
               for i in items[:6] if isinstance(i, dict) and i.get("title")]
        return res or None


def clean(s, n):
    """去掉換行與多餘空白，限制長度；只保留 ** 強調，避免任何 HTML。"""
    s = re.sub(r"[<>]", "", str(s))
    s = re.sub(r"\s+", " ", s).strip()
    if s.count("**") % 2:
        s = s.replace("**", "")
    return s[:n]
