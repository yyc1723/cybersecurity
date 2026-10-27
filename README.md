# 資安警訊雷達

每小時自動彙整全球資安警訊，AI 產生中文摘要，給同事一個網頁查看。全部使用免費服務。

```
GitHub Actions（每小時）
  ├─ 抓：CISA KEV、NVD、Microsoft MSRC、TWCERT/CC
  ├─ 篩：依產品清單與 CVSS 分等級，同一 CVE 合併
  ├─ AI：Gemini 產生中文標題與三點重點（沒有金鑰也能跑，改用原文擷取）
  └─ 資料有變化才 commit → Cloudflare Pages 自動部署（前面掛 Access 限公司信箱）
```

## 檔案說明

| 位置 | 用途 |
|---|---|
| `site/` | 網站本體（純 HTML／CSS／JS，沒有任何第三方套件） |
| `site/data/events.json` | 網站讀取的資料，由排程自動產生 |
| `site/_headers` | Cloudflare 安全標頭（CSP、禁止被嵌入等） |
| `scripts/radar/config.py` | **要調整收錄範圍就改這裡**：產品清單、代表色、等級門檻 |
| `scripts/radar/pipeline.py` | 主流程 |
| `data/store.json` | 排程的內部狀態（上次抓到哪裡），自動產生，不會上網站 |
| `.github/workflows/update.yml` | 每小時執行的排程 |
| `tests/` | 用假資料測試整個流程 |

---

## 第一次設定（約 30 分鐘）

### 步驟 1：申請 Gemini API 金鑰

1. 到 [Google AI Studio](https://aistudio.google.com/)，用 Google 帳號登入。
2. 進入 API keys 頁面，按 **Create API key**，複製金鑰（之後只會用在 GitHub Secrets，不要貼到任何檔案裡）。

> 免費額度每分鐘次數不多，程式已設定每次最多呼叫 12 次、每次間隔 7 秒；沒處理完的下一小時會接著做。

### 步驟 2：建立 GitHub 公開 repo 並上傳檔案

1. GitHub 右上角 **+** → **New repository**，名稱例如 `sec-radar`，選 **Public**，按 **Create repository**。
2. 在新 repo 頁面按 **uploading an existing file**，把這個資料夾裡**除了 `.github` 以外**的所有檔案與資料夾拖進去，按 **Commit changes**。
3. 建立排程檔（網頁上傳常會漏掉以「.」開頭的資料夾，所以手動建）：
   - 按 **Add file → Create new file**
   - 檔名輸入 `.github/workflows/update.yml`（輸入斜線會自動變成資料夾）
   - 把本資料夾 `.github/workflows/update.yml` 的內容整個貼上，按 **Commit changes**。

> 公開 repo 的 GitHub Actions 免費，不會用到你其他私人 repo 的分鐘數。repo 裡只有程式和公開的資安資訊，金鑰放在 Secrets 不會外流。

### 步驟 3：設定金鑰

repo 的 **Settings → Secrets and variables → Actions → New repository secret**：

| Name | Secret | 必要 |
|---|---|---|
| `GEMINI_API_KEY` | 步驟 1 的金鑰 | 建議（沒有就顯示英文原文擷取） |
| `NVD_API_KEY` | 到 NVD 網站免費申請的 API key | 選用（有的話抓得比較快） |

想換 AI 模型：同一頁切到 **Variables** 分頁，新增 `GEMINI_MODEL`（預設 `gemini-3.5-flash-lite`）。

### 步驟 4：手動跑第一次

1. repo 上方 **Actions** 分頁，若出現提示就按啟用。
2. 左側點 **更新資安警訊** → 右側 **Run workflow** → **Run workflow**。
3. 約 3～8 分鐘跑完，綠色勾勾代表成功；repo 裡會多一個「data: 更新資安警訊」的 commit。
4. 第一次會抓過去 7 天，AI 一次最多處理 12 則，其餘接下來幾小時會陸續補上中文摘要。

**如果失敗、錯誤訊息有 `403` 或 `Permission denied`**：到 **Settings → Actions → General → Workflow permissions**，選 **Read and write permissions** 後儲存，再跑一次。

### 步驟 5：用 Cloudflare Pages 上線

1. 登入 Cloudflare 後台，進入 **Workers & Pages**。
2. **Create application → Pages → Connect to Git**，選 **GitHub** 並授權，挑選 `sec-radar` repo，按 **Begin setup**。
3. 建置設定：
   - Framework preset：**None**
   - Build command：**留空**
   - Build output directory：**`site`**
4. 按 **Save and Deploy**。完成後會得到 `https://專案名稱.pages.dev` 網址。

之後排程每次 commit 新資料，Cloudflare 會自動重新部署，不用再手動處理。

### 步驟 6：用 Cloudflare Access 限制只有同事能看

1. 在 Pages 專案的 **Settings** 找到 **Enable access policy** 並啟用（預設只保護預覽網址）。
2. 按 **Manage** 進入 Access 應用程式設定 → **Configure**，在 **Public hostname** 把 **Subdomain** 欄位的 `*` 刪掉後儲存（若出現名稱重複的錯誤，改一下 Application name）。這樣正式網址 `專案名稱.pages.dev` 也會被保護。
3. 回到 Pages 專案 **Settings**，再按一次 **Enable access policy**，把預覽網址也重新保護起來。
4. 到 Zero Trust 後台的 Access 應用程式，編輯這個應用的 Policy：Include 規則選 **Emails ending in**，填入 `@你們公司網域`。
5. 同事開網址時輸入公司信箱，收到驗證碼即可進入。免費方案支援 50 人以內。

---

## 日常調整

- **新增或刪除產品**：編輯 `scripts/radar/config.py` 的 `PRODUCTS`，照現有格式加一筆，`group` 填分組名稱。`mine=True` 代表預設勾選在「我負責的產品」，且門檻放寬到 CVSS 7。
- **改等級門檻**：同檔案上方的 `CRIT_CVSS`、`HIGH_CVSS`、`MINE_CVSS`。
- **立即更新**：Actions → 更新資安警訊 → Run workflow。

## 收錄規則

| 等級 | 條件 |
|---|---|
| 緊急 | 列入 CISA KEV（已遭利用），或常見產品 CVSS ≥ 9.0，或微軟月更新含已遭利用漏洞 |
| 高 | 常見產品 CVSS 8.0～8.9 |
| 注意 | 預設負責產品（微軟系列）CVSS 7.0～7.9 |

- 不在產品清單內的漏洞一律不收（例如冷門 WordPress 外掛、Plex），即使已列入 KEV。
- TWCERT/CC 新聞全部收錄，放在網頁最右欄；標題含緊急、零時差、遭利用等字會標示「重要」。
- 同一產品同一天有 2 個以上漏洞列入 KEV，會合併成一張卡。
- 同一產品同一天有 3 個以上 CVE 會合併成一張卡。
- 微軟的個別 CVE 不逐一列出，改成每月一張「例行安全更新」摘要卡。
- NVD 剛公布、尚未評分的 CVE 會先略過，等評分後自動補進來。

## 注意事項

- **Cloudflare Pages 免費方案每月 500 次部署**：程式只在資料真的有變化時才 commit，正常約每天 5～15 次，在額度內。
- **GitHub 排程可能延遲**：尖峰時段可能晚 5～30 分鐘才執行，屬正常現象。repo 若 60 天完全沒有活動，GitHub 會暫停排程，但本專案每次更新資料都會產生 commit，通常不會發生。
- **AI 摘要可能有誤**：每張卡都附原始公告連結，重要決策請以原文為準。

## 本機測試（選用）

```bash
./tests/run_fixtures.sh   # 用假資料跑完整流程，不連網、不呼叫 AI
```
