"""主流程：抓資料 → 比對產品 → 判斷等級 → 合併去重 → AI 摘要 → 輸出網站資料。"""
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

from . import config, sources
from .ai import AI, clean

UTC = timezone.utc
TPE = timezone(timedelta(hours=8))
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
STORE = os.path.join(ROOT, "data", "store.json")
PUBLIC = os.path.join(ROOT, "site", "data", "events.json")
SEV_RANK = {"crit": 0, "high": 1, "note": 2}
PMAP = {p["name"]: p for p in config.PRODUCTS}
MINE = [p["name"] for p in config.PRODUCTS if p.get("mine")]


# ---------------- 工具 ----------------
def now():
    return datetime.now(UTC)


def iso(dt):
    return dt.astimezone(UTC).isoformat(timespec="seconds") if dt else None


def parse(s):
    return datetime.fromisoformat(s) if s else None


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def dump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write("\n")


def match_products(text, cpes=(), zh=False):
    text = text or ""
    found = []
    for p in config.PRODUCTS:
        hit = False
        for pat in p.get("cpe", []):
            if any(c == pat or c.startswith(pat + ":") or (":" not in pat and c.split(":")[0] == pat) for c in cpes):
                hit = True
                break
        if not hit:
            hit = any(re.search(k, text, re.I) for k in p.get("kw", []))
        if not hit and zh:
            hit = any(k.lower() in text.lower() for k in config.ZH_KW.get(p["name"], []))
        if hit:
            found.append(p["name"])
    # Windows Server 很容易被泛稱命中；若同時命中更精確的微軟產品，就只留精確的
    specific = {"IIS", "ASP.NET", ".NET", "SQL Server", "Exchange", "Office"}
    if "Windows Server" in found and specific & set(found):
        found.remove("Windows Server")
    return found


def classify(cvss, products, kev=False):
    if kev:
        return "crit"
    if not products or cvss is None:
        return None
    if cvss >= config.CRIT_CVSS:
        return "crit"
    if cvss >= config.HIGH_CVSS:
        return "high"
    if cvss >= config.MINE_CVSS and any(p in MINE for p in products):
        return "note"
    return None


def worse(a, b):
    return min([x for x in (a, b) if x], key=lambda s: SEV_RANK[s]) if (a or b) else None


def fmt_cvss(x):
    return f"{x:.1f}" if isinstance(x, (int, float)) else None


def month_zh(uid):
    months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
    m = uid.split("-")[-1][:3].lower()
    return f"{months.index(m) + 1} 月" if m in months else uid + " "


def tpe_date(dt):
    return dt.astimezone(TPE).strftime("%Y-%m-%d")


# ---------------- 事件建立 ----------------
def new_event(eid, kind, **kw):
    t = iso(now())
    ev = dict(id=eid, kind=kind, title="", sub="", sev=None, kev=False, ransomware=False, products=[], cves=[],
              cvss=None, published=t, first_seen=t, updated=t, src="", url="", pts=[], ai=False, raw={})
    ev.update(kw)
    return ev


def set_sub(ev):
    if ev["kind"] == "cve":
        bits = [ev["cves"][0]]
        if ev["cvss"] is not None:
            bits.append(f"CVSS {fmt_cvss(ev['cvss'])}")
        if ev.get("ransomware"):
            bits.append("已被勒索軟體利用")
        ev["sub"] = " · ".join(bits)
    elif ev["kind"] == "group":
        ev["sub"] = f"{len(ev['cves'])} 個 CVE · 最高 CVSS {fmt_cvss(ev['cvss'])}"
    elif ev["kind"] == "msrc":
        r = ev["raw"]
        ev["sub"] = f"{r['total']} 個 CVE · {len(r['exploited'])} 個已遭利用 · {r['critical']} 個重大"
    elif ev["kind"] == "twcert":
        ev["sub"] = ev["src"]


def fallback(ev):
    """沒有 AI 時的規則式摘要（標題與重點）。"""
    r, label = ev["raw"], (PMAP.get(ev["products"][0], config.OTHER)["label"] if ev["products"] else "")
    if ev["kind"] == "cve":
        ev["title"] = ev["title"] or clean(r.get("name") or f"{label} 漏洞 {ev['cves'][0]}", 40)
        pts = [clean(r.get("desc", ""), 140)]
        if ev["kev"]:
            pts.append("**已列入 CISA KEV 已遭利用清單**，請優先處理。")
        pts.append(clean(r.get("action") or "請依原廠公告更新至修補版本，並檢查相關存取紀錄。", 120))
    elif ev["kind"] == "group":
        ev["title"] = ev["title"] or f"{label} 多個高風險漏洞"
        pts = [f"同日公布 {len(ev['cves'])} 個漏洞，最高 CVSS {fmt_cvss(ev['cvss'])}。",
               clean(r.get("descs", [""])[0], 140), "請依原廠公告確認受影響版本並排程更新。"]
    elif ev["kind"] == "msrc":
        ev["title"] = ev["title"] or f"Microsoft {month_zh(r['id'])}例行安全更新"
        ex = "、".join(c for c, _ in r["exploited"][:4])
        pts = [f"本月共修補 {r['total']} 個漏洞，其中 {r['critical']} 個為重大等級。",
               f"**已遭利用：{ex}**" if ex else "目前未標示已遭利用的漏洞。",
               "請確認 Windows Update／WSUS 已部署本月累積更新。"]
    else:
        ev["title"] = ev["title"] or clean(r.get("title", ""), 40)
        pts = [clean(r.get("desc", ""), 150) or "詳見原始公告。"]
    ev["pts"] = [p for p in pts if p][:3]


def ai_context(ev):
    r = ev["raw"]
    base = dict(類型=ev["kind"], 產品=ev["products"], CVE=ev["cves"][:10], CVSS=ev["cvss"],
                已遭利用=ev["kev"], 勒索軟體利用=ev.get("ransomware", False), 發布日期=ev["published"][:10])
    if ev["kind"] == "cve":
        base.update(名稱=r.get("name"), 描述=r.get("desc"), 建議處置=r.get("action"))
    elif ev["kind"] == "group":
        base.update(描述=[d[:300] for d in r.get("descs", [])[:8]])
    elif ev["kind"] == "msrc":
        base.update(月份=r["id"], 總數=r["total"], 重大=r["critical"],
                    已遭利用=[f"{c} {t}" for c, t in r["exploited"]], 先行公開=[f"{c} {t}" for c, t in r["public"]])
    else:
        base.update(新聞標題=r.get("title"), 內容=r.get("desc"))
    return base


# ---------------- 主流程 ----------------
def run():
    t0 = now()
    store = load(STORE, {})
    events = {e["id"]: e for e in store.get("events", [])}
    first = not store.get("events")
    status = {}
    default_since = t0 - timedelta(days=config.FIRST_RUN_DAYS)
    nvd_key = os.environ.get("NVD_API_KEY", "").strip() or None

    def upsert(ev):
        old = events.get(ev["id"])
        if not old:
            events[ev["id"]] = ev
            return ev
        changed = False
        for k in ("cvss",):
            if ev[k] is not None and ev[k] != old[k]:
                old[k] = max(old[k] or 0, ev[k])
                changed = True
        sev = worse(old["sev"], ev["sev"])
        if sev != old["sev"]:
            old["sev"], changed = sev, True
        new_cves = sorted(set(old["cves"]) | set(ev["cves"]))
        if new_cves != old["cves"]:
            old["cves"], changed = new_cves, True
            old["raw"] = ev["raw"]
            old["ai"] = False
        if changed:
            old["updated"] = iso(now())
        return old

    # ---- NVD ----
    candidates = []
    try:
        since = parse(store.get("nvd_last")) - timedelta(hours=1) if store.get("nvd_last") else default_since
        for it in sources.fetch_nvd(since, t0, nvd_key):
            if it["source"] == "secure@microsoft.com":
                continue  # 微軟漏洞改由 MSRC 月度摘要彙整，避免洗版
            prods = match_products(it["desc"], it["cpes"])
            sev = classify(it["cvss"], prods)
            if sev:
                candidates.append((it, prods, sev))
        store["nvd_last"] = iso(t0)
        status["NVD"] = True
    except Exception as e:
        print(f"[NVD] 失敗：{e}")
        status["NVD"] = False

    groups = {}
    for it, prods, sev in candidates:
        groups.setdefault((prods[0], tpe_date(it["published"])), []).append((it, prods, sev))
    for (prod, day), items in groups.items():
        if len(items) >= config.GROUP_MIN:
            all_prods = sorted({p for _, ps, _ in items for p in ps}, key=lambda p: p != prod)
            ev = new_event(f"grp:{prod}:{day}", "group", products=all_prods,
                           cves=sorted(i["cve"] for i, _, _ in items),
                           cvss=max(i["cvss"] for i, _, _ in items),
                           sev=min((s for _, _, s in items), key=lambda s: SEV_RANK[s]),
                           published=iso(min(i["published"] for i, _, _ in items)), src="NVD",
                           url=f"https://nvd.nist.gov/vuln/search/results?query={items[0][0]['cve']}",
                           raw=dict(descs=[i["desc"] for i, _, _ in sorted(items, key=lambda x: -x[0]["cvss"])]))
            upsert(ev)
        else:
            for it, prods, sev in items:
                ev = new_event(it["cve"], "cve", products=prods, cves=[it["cve"]], cvss=it["cvss"], sev=sev,
                               published=iso(it["published"]), src="NVD",
                               url=f"https://nvd.nist.gov/vuln/detail/{it['cve']}",
                               raw=dict(desc=it["desc"], refs=it["refs"]))
                upsert(ev)

    # ---- CISA KEV ----
    try:
        since = parse(store["kev_last"]) - timedelta(days=2) if store.get("kev_last") else default_since
        enrich = 0
        for k in sources.fetch_kev(since):
            text = f"{k['vendor']} {k['product']} {k['name']} {k['desc']}"
            prods = match_products(text) or ["其他"]
            raw = dict(name=k["name"], desc=k["desc"], action=k["action"], vendor=k["vendor"], product=k["product"])
            old = events.get(k["cve"])
            if old:
                if not old["kev"]:
                    old.update(kev=True, sev="crit", ransomware=k["ransomware"], ai=False, updated=iso(now()))
                    old["raw"].update({k: v for k, v in raw.items() if k != "desc" or not old["raw"].get("desc")})
                continue
            cvss = None
            if enrich < 5:
                enrich += 1
                try:
                    one = sources.fetch_nvd_one(k["cve"], nvd_key)
                    cvss = one["cvss"] if one else None
                except Exception:
                    pass
            ev = new_event(k["cve"], "cve", products=prods, cves=[k["cve"]], cvss=cvss, sev="crit", kev=True,
                           ransomware=k["ransomware"], published=iso(k["added"]), src="CISA KEV",
                           url=(k["urls"] or [f"https://nvd.nist.gov/vuln/detail/{k['cve']}"])[0], raw=raw)
            events[ev["id"]] = ev
        store["kev_last"] = iso(t0)
        status["CISA KEV"] = True
    except Exception as e:
        print(f"[KEV] 失敗：{e}")
        status["CISA KEV"] = False

    # ---- Microsoft MSRC ----
    try:
        done = store.get("msrc_done", [])
        for m in sources.fetch_msrc(set(done), t0 - timedelta(days=35)):
            prods = [p for p in match_products(m["prod_text"]) if PMAP.get(p, {}).get("mine")] or ["Windows Server"]
            if "Windows Server" not in prods:
                prods.insert(0, "Windows Server")
            sev = "crit" if m["exploited"] else "high"
            ev = new_event(f"msrc:{m['id']}", "msrc", products=prods,
                           cves=[c for c, _ in m["exploited"]][:10], sev=sev, kev=bool(m["exploited"]),
                           published=iso(m["released"]), src="Microsoft MSRC", url=m["url"],
                           raw=dict(id=m["id"], total=m["total"], critical=m["critical"],
                                    exploited=m["exploited"], public=m["public"]))
            events[ev["id"]] = ev
            done.append(m["id"])
        store["msrc_done"] = done[-24:]
        status["Microsoft MSRC"] = True
    except Exception as e:
        print(f"[MSRC] 失敗：{e}")
        status["Microsoft MSRC"] = False

    # ---- TWCERT/CC ----
    try:
        for n in sources.fetch_twcert(default_since if first else t0 - timedelta(days=3)):
            eid = "tw:" + hashlib.sha1(n["link"].encode()).hexdigest()[:12]
            if eid in events:
                continue
            prods = match_products(f"{n['title']} {n['desc']}", zh=True) or ["其他"]
            sev = "high" if any(w in n["title"] for w in config.TW_HIGH_WORDS) else "note"
            events[eid] = new_event(eid, "twcert", products=prods, sev=sev, published=iso(n["published"]),
                                    src=n["src"], url=n["link"], raw=dict(title=n["title"], desc=n["desc"]))
        status["TWCERT/CC"] = True
    except Exception as e:
        print(f"[TWCERT] 失敗：{e}")
        status["TWCERT/CC"] = False

    # ---- 清除過舊 ----
    cutoff = t0 - timedelta(days=config.KEEP_DAYS)
    events = {k: v for k, v in events.items() if parse(v["published"]) >= cutoff}

    # ---- 摘要（AI 優先，否則規則式）----
    ai = AI()
    todo_list = list(events.values())
    todo_list.sort(key=lambda e: (SEV_RANK[e["sev"]], -parse(e["published"]).timestamp()))
    for ev in todo_list:
        set_sub(ev)
        if ev["ai"]:
            continue
        res = ai.summarize(ai_context(ev)) if ai.available else None
        if res:
            ev["title"], ev["pts"], ev["ai"] = res["title"], res["pts"], True
        elif not ev["pts"] or not ev["title"]:
            fallback(ev)
    print(f"[AI] 本次呼叫 {ai.calls} 次（模型 {ai.model}）")

    # ---- 本日應辦事項（台灣時間每天 07:00 後更新一次）----
    today = t0.astimezone(TPE).strftime("%Y-%m-%d")
    todo = store.get("todo", {})
    if todo.get("date") != today and t0.astimezone(TPE).hour >= 7:
        recent = [e for e in events.values() if e["sev"] in ("crit", "high")
                  and max(parse(e["published"]), parse(e["first_seen"])) >= t0 - timedelta(days=3)]
        recent.sort(key=lambda e: (not any(p in MINE for p in e["products"]), SEV_RANK[e["sev"]]))
        brief = [dict(標題=e["title"], 等級=e["sev"], 產品=e["products"], 本單位=any(p in MINE for p in e["products"]),
                      重點=e["pts"]) for e in recent[:15]]
        items = ai.todo(brief, MINE) if brief else []
        if items is None:
            items = [dict(title=clean(f"處理：{e['title']}", 30), desc=clean((e["pts"] or [""])[-1].replace("**", ""), 70))
                     for e in recent[:6]]
        todo = dict(date=today, items=items, ai=ai.calls > 0 and bool(items))
        store["todo"] = todo

    # ---- 輸出 ----
    store["events"] = sorted(events.values(), key=lambda e: e["published"], reverse=True)
    dump(STORE, store)

    public = dict(
        products=[{k: p[k] for k in ("name", "abbr", "label", "color", "text", "group")} | {"mine": bool(p.get("mine"))}
                  for p in config.PRODUCTS + [config.OTHER]],
        todo=todo,
        sources=status,
        events=[{k: e[k] for k in ("id", "kind", "title", "sub", "sev", "kev", "ransomware", "products", "cves",
                                   "cvss", "published", "first_seen", "src", "url", "pts", "ai")}
                for e in store["events"] if e["sev"]],
    )
    old = load(PUBLIC, {})
    old_body = {k: v for k, v in old.items() if k != "generated"}
    if old_body == public:
        print("[輸出] 內容沒有變化，不更新網站資料")
        return False
    public = dict(generated=iso(t0), **public)
    dump(PUBLIC, public)
    print(f"[輸出] {len(public['events'])} 則事件，來源狀態 {status}")
    return True
