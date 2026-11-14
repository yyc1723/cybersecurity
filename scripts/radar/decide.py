"""Gemini Decisions API（gemini-decision-1）：用是非題判斷產品、是否為資安新聞、是否已遭利用。
不產生文字，額度比一般模型寬很多。任何錯誤都回傳 None，呼叫端會退回原本的規則判斷。"""
import os
import time
import urllib.error

from . import config
from .net import post_json

API = "https://generativelanguage.googleapis.com/v1beta/decisions"
MODEL = "gemini-decision-1"


class Decider:
    def __init__(self):
        self.key = os.environ.get("GEMINI_API_KEY", "").strip()
        self.disabled = not self.key or not config.DECISION_ENABLED
        self.calls = 0
        self.last = 0.0

    @property
    def available(self):
        return not self.disabled and self.calls < config.DECISION_MAX_CALLS

    def ask(self, text, questions):
        """questions: {id: {type, instructions, ...}}。回傳 {id: answer} 或 None。"""
        if not self.available:
            return None
        wait = config.DECISION_GAP_SECONDS - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        body = {"model": MODEL, "input": text[:6000], "questions": questions}
        for attempt in range(2):
            try:
                self.calls += 1
                self.last = time.time()
                res = post_json(API, body, headers={"x-goog-api-key": self.key}, timeout=30)
                answers = res.get("answers")
                return answers if isinstance(answers, dict) else None
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt == 0:
                    time.sleep(20)
                    continue
                if e.code in (400, 401, 403, 404, 429):
                    print(f"[判斷] Decisions API 停用：HTTP {e.code}，本次改用規則判斷")
                    self.disabled = True
                return None
            except Exception as e:
                print(f"[判斷] 呼叫失敗：{type(e).__name__}")
                return None
        return None

    # ---------- 具體用途 ----------
    def products(self, text, candidates, news=False):
        """從產品清單中判斷「真正受影響的產品本身」。回傳產品名稱清單，失敗回傳 None。"""
        cands = [p for p in config.PRODUCTS if p["name"] in candidates] if candidates else config.PRODUCTS
        qs = {}
        for i, p in enumerate(cands):
            what = config.DECISION_DESC.get(p["name"], p["label"])
            if news:
                ins = f"Does this article report a security vulnerability, attack, or patch affecting {what} itself?"
            else:
                ins = (f"Is this vulnerability in {what} itself (the official product or its official components), "
                       f"rather than in a third-party library, package, module, plugin, extension, or application "
                       f"that merely uses, runs on, or is written for {what}?")
            qs[f"p{i}"] = {"type": "noul", "instructions": ins}
        ans = self.ask(text, qs)
        if ans is None:
            return None
        out = []
        for i, p in enumerate(cands):
            a = ans.get(f"p{i}") or {}
            if isinstance(a.get("noul"), (int, float)) and a["noul"] >= config.DECISION_THRESHOLD:
                out.append(p["name"])
        return out

    def news(self, text, need_filter):
        """新聞判斷：是否資安相關、是否重要（已遭利用／已發生攻擊或外洩／緊急警訊）。失敗回傳 None。"""
        qs = {
            "important": {"type": "noul", "instructions":
                          "Does the article report a vulnerability that is being actively exploited, a zero-day, "
                          "a confirmed cyberattack or data breach, or an urgent official security warning?"},
        }
        if need_filter:
            qs["security"] = {"type": "noul", "instructions":
                              "Is this article mainly about cybersecurity, such as vulnerabilities, security patches, "
                              "cyberattacks, data breaches, malware, ransomware, phishing, or fraud using hacked data?"}
        ans = self.ask(text, qs)
        if ans is None:
            return None

        def p(k):
            v = (ans.get(k) or {}).get("noul")
            return v if isinstance(v, (int, float)) else None

        sec, imp = p("security"), p("important")
        if imp is None or (need_filter and sec is None):
            return None
        return dict(security=(sec >= config.DECISION_THRESHOLD) if need_filter else True,
                    important=imp >= config.DECISION_THRESHOLD)
