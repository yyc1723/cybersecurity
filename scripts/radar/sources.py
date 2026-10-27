"""各資料來源的抓取與解析。每個函式都回傳「原始項目」清單，交給 build.py 整理成事件。"""
import html
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from . import config
from .net import get, get_json

UTC = timezone.utc


def _iso(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _parse_dt(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# ---------------- CISA KEV ----------------
def fetch_kev(since):
    """回傳 since 之後新增到 KEV 的項目。"""
    data = get_json(config.KEV_URL, fixture="kev.json")
    out = []
    for v in data.get("vulnerabilities", []):
        added = _parse_dt(v.get("dateAdded"))
        if not added or added.date() < since.date():
            continue
        notes = v.get("notes") or ""
        urls = [u.strip() for u in re.split(r"[;\s]+", notes) if u.strip().startswith("https://")]
        out.append(dict(
            cve=v.get("cveID", ""), vendor=v.get("vendorProject", ""), product=v.get("product", ""),
            name=v.get("vulnerabilityName", ""), desc=v.get("shortDescription", ""),
            action=v.get("requiredAction", ""), added=added, due=v.get("dueDate", ""),
            ransomware=(v.get("knownRansomwareCampaignUse") == "Known"), urls=urls[:3],
        ))
    return out


# ---------------- NVD ----------------
def _cvss(metrics):
    """取 CVSS 分數：優先 v4 → v3.1 → v3.0；同版本優先 Primary（NVD 自評），否則取最高。"""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        prim = [m for m in arr if m.get("type") == "Primary"]
        pick = prim[0] if prim else max(arr, key=lambda m: m.get("cvssData", {}).get("baseScore", 0))
        d = pick.get("cvssData", {})
        if "baseScore" in d:
            return float(d["baseScore"]), d.get("version", key[-2:])
    return None, None


def _cpes(cve):
    out = set()
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                parts = (m.get("criteria") or "").split(":")
                if len(parts) > 4:
                    out.add(f"{parts[3]}:{parts[4]}")
    return sorted(out)


def _parse_nvd_item(item):
    cve = item.get("cve", {})
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, ver = _cvss(cve.get("metrics", {}) or {})
    refs = [r.get("url") for r in cve.get("references", []) if (r.get("url") or "").startswith("https://")]
    return dict(
        cve=cve.get("id", ""), published=_parse_dt(cve.get("published")), desc=desc,
        cvss=score, cvss_ver=ver, cpes=_cpes(cve), source=cve.get("sourceIdentifier", ""),
        refs=refs[:5], status=cve.get("vulnStatus", ""),
    )


def _nvd_headers(api_key):
    return {"apiKey": api_key} if api_key else {}


def _nvd_pages(params, api_key, fixture):
    out, start = [], 0
    gap = 1.0 if api_key else 6.5  # 無金鑰：每 30 秒最多 5 次
    while True:
        q = dict(params, resultsPerPage=2000, startIndex=start)
        url = config.NVD_URL + "?" + urllib.parse.urlencode(q)
        data = get_json(url, headers=_nvd_headers(api_key), fixture=fixture)
        vulns = data.get("vulnerabilities", [])
        out += [_parse_nvd_item(v) for v in vulns]
        start += len(vulns)
        if not vulns or start >= data.get("totalResults", 0) or fixture:
            break
        time.sleep(gap)
    time.sleep(gap)
    return out


def fetch_nvd(since, until, api_key=None):
    """抓 since～until 之間「新發布」與「新修改」的 CVE（修改用來補抓後來才評分的）。"""
    pub = _nvd_pages({"pubStartDate": _iso(since), "pubEndDate": _iso(until)}, api_key, "nvd_pub.json")
    mod = _nvd_pages({"lastModStartDate": _iso(since), "lastModEndDate": _iso(until)}, api_key, "nvd_mod.json")
    seen, out = set(), []
    recent = until - timedelta(days=30)
    for it in pub + mod:
        if it["cve"] in seen or not it["published"] or it["published"] < recent:
            continue
        if it["status"] == "Rejected":
            continue
        seen.add(it["cve"])
        out.append(it)
    return out


def fetch_nvd_one(cve_id, api_key=None):
    url = config.NVD_URL + "?" + urllib.parse.urlencode({"cveId": cve_id})
    data = get_json(url, headers=_nvd_headers(api_key), fixture=f"nvd_{cve_id}.json")
    v = data.get("vulnerabilities", [])
    time.sleep(1.0 if api_key else 6.5)
    return _parse_nvd_item(v[0]) if v else None


# ---------------- Microsoft MSRC ----------------
def fetch_msrc(done_ids, since):
    """找出還沒處理過的微軟月度更新，整理成摘要。"""
    data = get_json(config.MSRC_UPDATES_URL, fixture="msrc_updates.json")
    out = []
    for u in data.get("value", []):
        uid = u.get("ID")
        released = _parse_dt(u.get("InitialReleaseDate"))
        if not uid or uid in done_ids or not released or released < since:
            continue
        doc = get_json(u.get("CvrfUrl"), fixture=f"msrc_{uid}.json")
        names = {}
        for b in (doc.get("ProductTree", {}) or {}).get("FullProductName", []) or []:
            names[b.get("ProductID")] = b.get("Value", "")
        total, exploited, public, critical, prod_text = 0, [], [], 0, []
        for v in doc.get("Vulnerability", []) or []:
            total += 1
            cve = v.get("CVE", "")
            title = (v.get("Title") or {}).get("Value", "")
            threats = v.get("Threats", []) or []
            status = " ".join((t.get("Description") or {}).get("Value", "") for t in threats if t.get("Type") == 1)
            sev = " ".join((t.get("Description") or {}).get("Value", "") for t in threats if t.get("Type") == 3)
            if "Exploited:Yes" in status:
                exploited.append((cve, title))
            if "Publicly Disclosed:Yes" in status:
                public.append((cve, title))
            if "Critical" in sev:
                critical += 1
            for ps in v.get("ProductStatuses", []) or []:
                for pid in ps.get("ProductID", []) or []:
                    prod_text.append(names.get(pid, ""))
        out.append(dict(id=uid, released=released, total=total, exploited=exploited, public=public,
                        critical=critical, prod_text=" ".join(set(prod_text)),
                        url=f"https://msrc.microsoft.com/update-guide/releaseNote/{uid}"))
    return out


# ---------------- TWCERT/CC RSS ----------------
def _strip(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def fetch_twcert(since):
    out = []
    for i, (name, url) in enumerate(config.TWCERT_FEEDS):
        raw = get(url, fixture=f"twcert_{i}.xml")
        root = ET.fromstring(raw)
        for item in root.iter("item"):
            title = _strip(item.findtext("title"))
            link = (item.findtext("link") or "").strip()
            pub = item.findtext("pubDate")
            try:
                dt = parsedate_to_datetime(pub) if pub else None
            except (TypeError, ValueError):
                dt = None
            if dt and dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            if not title or not link.startswith("https://") or (dt and dt < since):
                continue
            out.append(dict(title=title, link=link, desc=_strip(item.findtext("description"))[:1200],
                            published=dt or datetime.now(UTC), src=name))
    return out
