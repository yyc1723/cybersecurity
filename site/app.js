// 資安警訊雷達：讀取 data/events.json 並畫出整個頁面。所有外部文字一律跳脫，不使用 innerHTML 帶入未處理的資料。
(function () {
  "use strict";
  const DAYS = 14;
  const LABEL = { crit: "緊急", high: "高", note: "注意" };
  const ORDER = { crit: 0, high: 1, note: 2 };
  const DAY = 86400000;
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (s) => esc(s).replace(/\*\*(.+?)\*\*/g, "<em>$1</em>");
  const safeUrl = (u) => (/^https:\/\//i.test(u || "") ? u : "#");
  const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const tpe = (iso) => new Date(new Date(iso).getTime() + 8 * 3600000); // 轉台灣時間後用 UTC getter 讀
  const md = (iso) => { const d = tpe(iso); return `${String(d.getUTCMonth() + 1).padStart(2, "0")}/${String(d.getUTCDate()).padStart(2, "0")}`; };
  const hm = (iso) => { const d = tpe(iso); return `${md(iso)} ${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`; };

  let DATA = null, PMETA = {}, mine = [], sev = "all";
  const store = {
    get() { try { const v = JSON.parse(localStorage.getItem("mine")); return Array.isArray(v) ? v : null; } catch (e) { return null; } },
    set(v) { try { localStorage.setItem("mine", JSON.stringify(v)); } catch (e) { /* 私密視窗等情況忽略 */ } },
  };
  const isMine = (e) => e.products.some((p) => mine.includes(p));
  const recent = (e, days) => Date.now() - Math.max(new Date(e.published), new Date(e.first_seen)) < days * DAY;
  const meta = (p) => PMETA[p] || PMETA["其他"] || { abbr: "?", label: p, color: "#8A8A85", text: "#fff" };

  // CSP 不允許 HTML 內的 style 屬性，所以顏色與寬度改用 data-* 標記後再以 JS 設定
  function paintVars(root) {
    root.querySelectorAll("[data-pc]").forEach((el) => {
      const m = meta(el.dataset.pc);
      el.style.setProperty("--pc", m.color);
      el.style.setProperty("--pc-t", m.text);
    });
    root.querySelectorAll("[data-w]").forEach((el) => el.style.setProperty("--w", el.dataset.w + "%"));
  }

  function shown() {
    const q = $("#q").value.trim().toLowerCase();
    let rows = DATA.events.filter((e) => e.kind !== "twcert" && (q ? true : recent(e, DAYS)));
    if (q) rows = rows.filter((e) => (e.title + e.sub + e.products.join() + e.cves.join() + e.pts.join()).toLowerCase().includes(q));
    if (sev !== "all") rows = rows.filter((e) => e.sev === sev);
    return rows.sort((a, b) => (isMine(b) - isMine(a)) || (ORDER[a.sev] - ORDER[b.sev]) || (new Date(b.published) - new Date(a.published)));
  }

  function drawDonut(rows) {
    const c = { crit: 0, high: 0, note: 0 };
    rows.forEach((e) => c[e.sev]++);
    const total = rows.length, r = 46, C = 2 * Math.PI * r;
    let off = 0, segs = "";
    ["crit", "high", "note"].forEach((k) => {
      if (!c[k]) return;
      const len = (c[k] / total) * C;
      segs += `<circle cx="60" cy="60" r="${r}" fill="none" stroke="${css("--" + k)}" stroke-width="13" stroke-linecap="round" stroke-dasharray="${Math.max(len - 6, 1)} ${C - len + 6}" stroke-dashoffset="${-off - 3}" transform="rotate(-90 60 60)"/>`;
      off += len;
    });
    $("#donut").innerHTML = `<circle cx="60" cy="60" r="${r}" fill="none" stroke="${css("--soft")}" stroke-width="13"/>${segs}
      <text x="60" y="61" text-anchor="middle" font-size="26">${total}</text>
      <text x="60" y="78" text-anchor="middle" font-size="10" fill="${css("--muted")}">起事件</text>`;
    const nNew = rows.filter((e) => Date.now() - new Date(e.first_seen) < DAY).length;
    $("#legend").innerHTML = ["crit", "high", "note"].map((k) => `<div><i class="${k}"></i>${LABEL[k]}<b>${c[k]}</b></div>`).join("") +
      `<div><i class="new"></i>24 小時內新增<b>${nNew}</b></div>`;
  }

  function drawTrend(rows) {
    const days = [];
    for (let i = 6; i >= 0; i--) days.push(md(new Date(Date.now() - i * DAY).toISOString()));
    const data = days.map((d) => { const o = { crit: 0, high: 0, note: 0 }; rows.filter((e) => md(e.published) === d).forEach((e) => o[e.sev]++); return o; });
    const max = Math.max(4, ...data.map((o) => o.crit + o.high + o.note));
    const step = max > 12 ? 5 : 2;
    const W = 258, H = 110, top = 8, bot = 20, left = 18, bw = 22, gap = (W - left - bw * 7) / 7, sc = (H - top - bot) / max;
    let g = "";
    for (let t = 0; t <= max; t += step) { const y = H - bot - t * sc; g += `<line x1="${left}" x2="${W}" y1="${y}" y2="${y}" stroke="${css("--line")}" stroke-width="1"/><text x="${left - 6}" y="${y + 3}" text-anchor="end">${t}</text>`; }
    data.forEach((o, i) => {
      const x = left + gap / 2 + i * (bw + gap); let y = H - bot;
      ["note", "high", "crit"].forEach((k) => { if (!o[k]) return; const h = o[k] * sc; y -= h; g += `<rect x="${x}" y="${y}" width="${bw}" height="${Math.max(h - 1.5, 1)}" rx="4" fill="${css("--" + k)}"/>`; });
      g += `<text x="${x + bw / 2}" y="${H - 5}" text-anchor="middle">${days[i].slice(3)}</text>`;
    });
    $("#trend").innerHTML = g;
  }

  function drawBars(rows) {
    const m = {};
    rows.forEach((e) => e.products.forEach((p) => { m[p] = m[p] || { crit: 0, high: 0, note: 0 }; m[p][e.sev]++; }));
    const list = Object.entries(m).map(([p, o]) => [p, o, o.crit + o.high + o.note]).sort((a, b) => b[2] - a[2]).slice(0, 8);
    if (!list.length) { $("#bars").innerHTML = '<div class="hint">近 14 天沒有事件</div>'; return; }
    const max = list[0][2];
    $("#bars").innerHTML = list.map(([p, o, n]) => `<div class="bar"><span>${esc(p)}</span><div class="track">${["crit", "high", "note"].map((k) => (o[k] ? `<span class="${k}" data-w="${((o[k] / max) * 100).toFixed(1)}"></span>` : "")).join("")}</div><b>${n}</b></div>`).join("");
    paintVars($("#bars"));
  }

  function renderChips() {
    const groups = {};
    DATA.products.forEach((p) => { if (p.name !== "其他") (groups[p.group] = groups[p.group] || []).push(p); });
    const order = DATA.groups || Object.keys(groups);
    $("#chips").innerHTML = order.filter((g) => groups[g]).map((g) => [g, groups[g]]).map(([g, ps]) => `<div class="chipgroup">${esc(g)}</div>` +
      ps.map((p) => `<button class="key chip" data-pc="${esc(p.name)}" aria-pressed="${mine.includes(p.name)}" data-p="${esc(p.name)}"><i></i>${esc(p.name)}</button>`).join("")).join("");
    $("#mineCnt").textContent = `已選 ${mine.length}`;
    paintVars($("#chips"));
  }

  function renderQuick(rows) {
    const list = [...rows].sort((a, b) => (ORDER[a.sev] - ORDER[b.sev]) || (new Date(b.published) - new Date(a.published))).slice(0, 12);
    $("#qlist").innerHTML = list.length ? list.map((e) => `<button class="qrow ${e.sev}" data-id="${esc(e.id)}" title="${esc(e.title)}"><i></i><span class="lv">${LABEL[e.sev]}</span><span class="tt">${esc(e.title)}</span><span class="sc">${e.cvss != null ? e.cvss.toFixed(1) : "—"}</span></button>`).join("")
      : '<div class="hint">目前沒有事件</div>';
  }

  function renderTodo() {
    const t = DATA.todo || {};
    const items = t.items || [];
    $("#todoNote").textContent = t.date ? `${t.date.slice(5).replace("-", "/")} · ${t.ai ? "AI 依今日緊急與高風險事件整理" : "依今日緊急與高風險事件整理"}` : "";
    $("#todo").innerHTML = items.length ? items.map((it, i) => `<div><span class="n">${i + 1}</span><span><strong>${esc(it.title)}</strong><p>${esc(it.desc)}</p></span></div>`).join("")
      : '<div class="todo-empty">近三天沒有緊急或高風險事件，維持例行更新即可。</div>';
  }

  function renderList() {
    const rows = shown();
    const q = $("#q").value.trim();
    $("#count").textContent = q ? `搜尋全部歷史 · 找到 ${rows.length} 則` : `近 ${DAYS} 天 · 顯示 ${rows.length} 則`;
    $("#list").innerHTML = rows.length ? rows.map((e, i) => {
      const m = meta(e.products[0]);
      const isNew = Date.now() - new Date(e.first_seen) < DAY;
      return `<article class="card ${e.sev}${e.kev ? " kev" : ""}" id="ev-${esc(e.id)}"><div class="blob" aria-hidden="true"></div><div class="inner">
      <div class="hd"><span class="num">${i + 1}</span>
        <div><h3>${esc(e.title)}</h3><div class="sub mono">${esc(e.sub)}</div></div>
        <div class="pills"><span class="pill sev">${LABEL[e.sev]}</span>${e.kev ? '<span class="pill kev">已遭利用</span>' : ""}${isNew ? '<span class="pill new">新增</span>' : ""}</div>
      </div>
      <div class="bd"><div class="prod"><div class="ic brand" data-pc="${esc(e.products[0])}">${esc(m.abbr)}</div><span>${esc(m.label)}</span></div>
        <ul>${e.pts.map((p) => `<li>${fmt(p)}</li>`).join("")}</ul></div>
      <div class="ft"><span class="tags">${e.products.map((p) => `<span>${esc(p)}</span>`).join("")}${e.ai ? "" : '<span>原文擷取</span>'}</span><span>${md(e.published)} · ${esc(e.src)} · <a href="${esc(safeUrl(e.url))}" target="_blank" rel="noopener noreferrer">原始公告 →</a></span></div>
    </div></article>`;
    }).join("") : `<div class="empty">${!DATA.events.some((x) => x.kind !== "twcert") ? "還沒有資料，等第一次排程執行完成後就會出現。" : q ? "找不到符合的事件，換個關鍵字試試。" : "這個等級目前沒有事件。"}</div>`;
    paintVars($("#list"));
  }

  let newsLimit = 8;
  function renderNews() {
    const all = DATA.events.filter((e) => e.kind === "twcert").sort((a, b) => new Date(b.published) - new Date(a.published));
    const list = all.slice(0, newsLimit);
    $("#news").innerHTML = list.length ? list.map((e) => {
      const tags = e.products.filter((p) => p !== "其他");
      return `<a class="nitem ${e.sev}" href="${esc(safeUrl(e.url))}" target="_blank" rel="noopener noreferrer">
        <span class="nmeta"><span class="mono">${md(e.published)}</span>${e.sev === "high" ? '<span class="nlv">重要</span>' : ""}${Date.now() - new Date(e.first_seen) < DAY ? '<span class="nnew">新</span>' : ""}</span>
        <strong>${esc(e.title)}</strong>
        ${e.pts[0] ? `<p>${esc(e.pts[0].replace(/\*\*/g, ""))}</p>` : ""}
        ${tags.length ? `<span class="ntags">${tags.map((p) => `<span data-pc="${esc(p)}"><i></i>${esc(p)}</span>`).join("")}</span>` : ""}
      </a>`;
    }).join("") : '<div class="hint">目前沒有 TWCERT/CC 新聞。</div>';
    $("#newsMore").hidden = all.length <= newsLimit;
    paintVars($("#news"));
  }

  function renderAll() {
    const base = DATA.events.filter((e) => e.kind !== "twcert" && recent(e, DAYS));
    drawDonut(base); drawTrend(base); drawBars(base); renderQuick(base); renderTodo(); renderList(); renderNews();
  }

  function bind() {
    $("#chips").addEventListener("click", (ev) => {
      const b = ev.target.closest(".chip"); if (!b) return;
      const p = b.dataset.p;
      mine = mine.includes(p) ? mine.filter((x) => x !== p) : [...mine, p];
      store.set(mine); renderChips(); renderList();
    });
    document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => {
      sev = b.dataset.sev;
      document.querySelectorAll(".seg button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      renderList();
    }));
    $("#q").addEventListener("input", renderList);
    $("#newsMore").addEventListener("click", () => { newsLimit += 8; renderNews(); });
    $("#qlist").addEventListener("click", (ev) => {
      const b = ev.target.closest(".qrow"); if (!b) return;
      let card = document.getElementById("ev-" + b.dataset.id);
      if (!card) {
        $("#q").value = ""; sev = "all";
        document.querySelectorAll(".seg button").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.sev === "all")));
        renderList(); card = document.getElementById("ev-" + b.dataset.id);
      }
      if (!card) return;
      const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
      card.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      card.classList.add("flash"); setTimeout(() => card.classList.remove("flash"), 1600);
    });
  }

  async function init() {
    try {
      const res = await fetch("data/events.json?t=" + Date.now(), { cache: "no-store" });
      if (!res.ok) throw new Error(res.status);
      DATA = await res.json();
    } catch (e) {
      $("#list").innerHTML = '<div class="empty">資料載入失敗，請稍後重新整理。</div>';
      return;
    }
    DATA.events = DATA.events || [];
    DATA.products = DATA.products || [];
    DATA.products.forEach((p) => (PMETA[p.name] = p));
    mine = store.get() || DATA.products.filter((p) => p.mine).map((p) => p.name);
    $("#updated").textContent = DATA.generated ? hm(DATA.generated) : "—";
    $("#range").textContent = `${md(new Date(Date.now() - (DAYS - 1) * DAY).toISOString())} – ${md(new Date().toISOString())} · 台灣時間`;
    const failed = Object.entries(DATA.sources || {}).filter(([, ok]) => !ok).map(([k]) => k);
    if (failed.length) $("#footer").insertAdjacentHTML("beforeend", ` · <span class="srcwarn">${esc(failed.join("、"))} 本次抓取失敗，資料可能不完整</span>`);
    renderChips(); bind(); renderAll();
  }
  init();
})();
