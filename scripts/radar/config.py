"""網站設定：產品清單、等級門檻、資料來源。改這個檔案就能調整收錄範圍。"""

# 比對規則版本：改了產品清單或規則後把數字加 1，下次執行會重新回看 FIRST_RUN_DAYS 天補抓
RULES_VERSION = 4
# AI 摘要格式版本：改了摘要格式就加 1，舊摘要會在之後幾次執行中逐步重新產生
AI_VERSION = 2

# ---------- 等級門檻 ----------
# 緊急：CISA KEV（已遭利用）或 CVSS >= CRIT_CVSS
# 高　：CVSS >= HIGH_CVSS
# 注意：「本單位」產品且 CVSS >= MINE_CVSS
CRIT_CVSS = 9.0
HIGH_CVSS = 8.0
MINE_CVSS = 7.0

# 同一產品同一天超過幾個 CVE 就合併成一張卡
GROUP_MIN = 2
# 首頁顯示天數（網頁端）／資料保留天數
KEEP_DAYS = 60
# 第一次執行往回抓幾天
FIRST_RUN_DAYS = 7
# 每次執行最多呼叫 AI 幾次（免費額度有限，剩下的下次再處理）；每次呼叫一次送 AI_BATCH 則
AI_MAX_CALLS = 12
AI_BATCH = 6
# 兩次 AI 呼叫間隔秒數（免費版每分鐘次數很少）
AI_GAP_SECONDS = 7
# Gemini 模型；想換模型可在 GitHub Secrets/Variables 設 GEMINI_MODEL 覆蓋
GEMINI_MODEL = "gemini-3.5-flash-lite"

# ---------- 資料來源 ----------
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
# 新聞來源（顯示在網頁右欄）
# filter=True：綜合新聞來源，只保留資安相關的
# summarize=False：只顯示標題與連結，不做摘要（若對轉載有疑慮可改成 False）
NEWS_FEEDS = [
    dict(name="TWCERT/CC 資安新聞", short="TWCERT", url="https://www.twcert.org.tw/tw/rss-104-1.xml", filter=False, summarize=True),
    dict(name="iThome", short="iThome", url="https://www.ithome.com.tw/rss", filter=True, summarize=True),
]
NEWS_SEC_WORDS = r"資安|漏洞|攻擊|駭客|勒索|零時差|釣魚|惡意|外洩|入侵|修補|CVE-\d|後門|殭屍|DDoS|APT|供應鏈攻擊|資料竊取"
# 新聞標題含這些字 → 標示「重要」
TW_HIGH_WORDS = ["緊急", "零時差", "已遭利用", "遭利用", "遭駭", "勒索", "重大漏洞", "警訊"]

# ---------- 產品清單 ----------
# 篩選標籤的分組順序
GROUP_ORDER = ['網路與資安設備', '作業系統與伺服器', '資料庫與應用系統', '開發與 AI 平台']
# name   : 顯示名稱（篩選標籤）
# abbr   : 卡片左側方塊上的縮寫
# label  : 方塊下方的小字
# color  : 代表色；text: 方塊文字顏色
# kw     : 描述文字比對用的正規表示式（不分大小寫）
# cpe    : NVD CPE 比對字串，格式 "廠商:產品"，只寫廠商代表該廠商全部產品
# mine   : True = 預設勾選在「我負責的產品」，且門檻放寬到 MINE_CVSS
# group  : 篩選標籤的分組
PRODUCTS = [
    # --- 本單位（Microsoft） ---
    dict(name="Windows Server", abbr="Win", label="Windows", color="#0078D4", text="#fff", mine=True, group="作業系統與伺服器",
         kw=[r"windows server", r"\bmicrosoft windows\b", r"\bwindows (smb|kerberos|ntlm|shell|kernel|rpc|tcp/ip|hyper-v|remote desktop|lsass)"],
         cpe=["microsoft:windows"]),
    dict(name="IIS", abbr="IIS", label="IIS", color="#0078D4", text="#fff", mine=True, group="作業系統與伺服器",
         kw=[r"internet information services", r"\biis\b"], cpe=["microsoft:internet_information_services"]),
    dict(name="ASP.NET", abbr="ASP", label="ASP.NET", color="#512BD4", text="#fff", mine=True, group="開發與 AI 平台",
         kw=[r"asp\.net"], cpe=["microsoft:asp.net"]),
    dict(name=".NET", abbr=".NET", label=".NET", color="#512BD4", text="#fff", mine=True, group="開發與 AI 平台",
         kw=[r"\.net framework", r"\.net core", r"\.net \d", r"\bdotnet\b"], cpe=["microsoft:.net"]),
    dict(name="SQL Server", abbr="SQL", label="SQL Server", color="#CC2927", text="#fff", mine=True, group="資料庫與應用系統",
         kw=[r"sql server"], cpe=["microsoft:sql_server"]),
    dict(name="Exchange", abbr="EX", label="Exchange", color="#0A64B7", text="#fff", mine=True, group="資料庫與應用系統",
         kw=[r"exchange server", r"microsoft exchange"], cpe=["microsoft:exchange_server"]),
    dict(name="Office", abbr="Off", label="Office", color="#D83B01", text="#fff", mine=True, group="資料庫與應用系統",
         kw=[r"microsoft office", r"\boutlook\b", r"microsoft (word|excel|powerpoint)", r"sharepoint"],
         cpe=["microsoft:office", "microsoft:outlook", "microsoft:sharepoint", "microsoft:365_apps"]),
    # --- 網路設備 ---
    dict(name="Fortinet", abbr="FG", label="Fortinet", color="#DA291C", text="#fff", group="網路與資安設備",
         kw=[r"\bfortinet\b", r"\bforti(os|gate|manager|analyzer|web|mail|proxy|client|switch|siem|sandbox|authenticator|nac|voice|ap)\b"],
         cpe=["fortinet"]),
    dict(name="Cisco", abbr="CS", label="Cisco", color="#1BA0D7", text="#fff", group="網路與資安設備",
         kw=[r"\bcisco\b"], cpe=["cisco"]),
    dict(name="Palo Alto", abbr="PA", label="Palo Alto", color="#FA582D", text="#fff", group="網路與資安設備",
         kw=[r"pan-os", r"palo alto networks", r"globalprotect"], cpe=["paloaltonetworks"]),
    dict(name="Ivanti", abbr="IV", label="Ivanti", color="#C8102E", text="#fff", group="網路與資安設備",
         kw=[r"\bivanti\b"], cpe=["ivanti"]),
    dict(name="Citrix", abbr="CTX", label="Citrix", color="#452170", text="#fff", group="網路與資安設備",
         kw=[r"\bcitrix\b", r"netscaler"], cpe=["citrix"]),
    dict(name="SonicWall", abbr="SW", label="SonicWall", color="#FF791A", text="#fff", group="網路與資安設備",
         kw=[r"sonicwall"], cpe=["sonicwall"]),
    dict(name="SD-WAN", abbr="WAN", label="SD-WAN", color="#5B6F82", text="#fff", group="網路與資安設備",
         kw=[r"velocloud", r"sd-wan"], cpe=["arista:velocloud", "vmware:sd-wan"]),
    # --- 伺服器與平台 ---
    dict(name="Linux", abbr="Lx", label="Linux 核心", color="#FCC624", text="#1E1E1C", group="作業系統與伺服器",
         kw=[r"linux kernel", r"\bksmbd\b"], cpe=["linux:linux_kernel"]),
    dict(name="VMware", abbr="VM", label="VMware", color="#607078", text="#fff", group="作業系統與伺服器",
         kw=[r"\bvmware\b", r"vcenter", r"\besxi\b"], cpe=["vmware", "broadcom:vmware"]),
    dict(name="Apache", abbr="APA", label="Apache", color="#D22128", text="#fff", group="作業系統與伺服器",
         kw=[r"apache http server", r"apache tomcat", r"\btomcat\b", r"apache struts", r"\blog4j\b"],
         cpe=["apache:http_server", "apache:tomcat", "apache:struts", "apache:log4j"]),
    dict(name="nginx", abbr="NGX", label="nginx", color="#009639", text="#fff", group="作業系統與伺服器",
         kw=[r"\bnginx\b"], cpe=["f5:nginx", "nginx:nginx"]),
    dict(name="OpenSSL", abbr="SSL", label="OpenSSL", color="#721412", text="#fff", group="作業系統與伺服器",
         kw=[r"\bopenssl\b"], cpe=["openssl:openssl"]),
    dict(name="OpenSSH", abbr="SSH", label="OpenSSH", color="#3A3A3A", text="#fff", group="作業系統與伺服器",
         kw=[r"\bopenssh\b"], cpe=["openbsd:openssh"]),
    dict(name="BIND", abbr="DNS", label="ISC BIND", color="#2B5797", text="#fff", group="作業系統與伺服器",
         kw=[r"\bbind 9\b", r"isc bind", r"\bbind9\b"], cpe=["isc:bind"]),
    dict(name="Oracle", abbr="ORA", label="Oracle", color="#C74634", text="#fff", group="資料庫與應用系統",
         kw=[r"oracle (database|weblogic|e-business|fusion middleware)", r"\bweblogic\b"],
         cpe=["oracle:weblogic", "oracle:database_server", "oracle:e-business_suite"]),
    dict(name="QNAP", abbr="QN", label="QNAP", color="#1C67B5", text="#fff", group="作業系統與伺服器",
         kw=[r"\bqnap\b", r"\bqts\b", r"quts hero"], cpe=["qnap"]),
    dict(name="Synology", abbr="SYN", label="Synology", color="#4D4D4D", text="#fff", group="作業系統與伺服器",
         kw=[r"\bsynology\b", r"\bdiskstation\b"], cpe=["synology"]),
    dict(name="Veeam", abbr="VB", label="Veeam", color="#00B336", text="#fff", group="作業系統與伺服器",
         kw=[r"\bveeam\b"], cpe=["veeam"]),
    # --- 開發與應用 ---
    dict(name="PHP", abbr="PHP", label="PHP", color="#777BB4", text="#fff", group="開發與 AI 平台",
         kw=[r"php-fpm", r"php-cgi", r"\bmod_php\b", r"\bphp (versions? )?[5-9]\.\d"], cpe=["php:php"]),
    dict(name="Java", abbr="Java", label="Java", color="#E76F00", text="#fff", group="開發與 AI 平台",
         kw=[r"java se", r"\bopenjdk\b", r"oracle java", r"\bgraalvm\b"], cpe=["oracle:jdk", "oracle:jre", "oracle:graalvm"]),
    dict(name="Node.js", abbr="Node", label="Node.js", color="#5FA04E", text="#fff", group="開發與 AI 平台",
         kw=[r"\bnode\.js\b"], cpe=["nodejs:node.js"]),
    dict(name="Go", abbr="Go", label="Go 語言", color="#00ADD8", text="#fff", group="開發與 AI 平台",
         kw=[r"\bgolang\b", r"go standard library", r"\bcrypto/(x509|tls)\b", r"\bnet/http\b", r"\bcmd/go\b", r"\bgo (before|prior to) 1\.\d"], cpe=["golang:go"]),
    dict(name="GitLab", abbr="GL", label="GitLab", color="#FC6D26", text="#fff", group="資料庫與應用系統",
         kw=[r"\bgitlab\b"], cpe=["gitlab"]),
    dict(name="Atlassian", abbr="ATL", label="Atlassian", color="#0052CC", text="#fff", group="資料庫與應用系統",
         kw=[r"\bconfluence\b", r"\bjira\b", r"\bbitbucket\b"], cpe=["atlassian"]),
    dict(name="Chrome", abbr="Chr", label="Chrome", color="#1A73E8", text="#fff", group="資料庫與應用系統",
         kw=[r"google chrome", r"\bchromium\b"], cpe=["google:chrome"]),
    dict(name="AI 平台", abbr="AI", label="AI 平台", color="#7B4DFF", text="#fff", group="開發與 AI 平台",
         kw=[r"\blangflow\b", r"\blitellm\b", r"\bollama\b", r"\bcomfyui\b", r"open webui", r"\bn8n\b", r"\bvllm\b"],
         cpe=["langflow", "litellm", "ollama", "n8n", "vllm"]),
    dict(name="憑證/CA", abbr="CA", label="憑證機構", color="#2E7D5B", text="#fff", group="網路與資安設備",
         kw=[r"certificate authority", r"root certificate", r"憑證", r"\bca\b.*(revok|distrust)"], cpe=[]),
]

# 只出現在 TWCERT 中文新聞時的中文關鍵字（補充比對）
ZH_KW = {
    "Windows Server": ["Windows"], "Exchange": ["Exchange"], "Office": ["Office", "Outlook", "SharePoint"],
    "SQL Server": ["SQL Server"], "IIS": ["IIS"], "ASP.NET": ["ASP.NET"], ".NET": [".NET"],
    "Linux": ["Linux 核心", "Linux"], "PHP": ["PHP"], "Java": ["Java"], "Node.js": ["Node.js"], "Go": ["Go 語言", "Golang"],
    "AI 平台": ["AI 平台", "Langflow", "LiteLLM", "Ollama", "n8n"], "憑證/CA": ["憑證"],
}

# 比對不到產品時 KEV 事件用的預設方塊
OTHER = dict(name="其他", abbr="?", label="其他", color="#8A8A85", text="#fff", group="其他")


# 結構化名稱比對（KEV 的「廠商 產品」欄位用）：寫小寫，會以完整單字比對
ALIASES = {
    "Windows Server": ["windows", "win32k", "windows server"], "IIS": ["internet information services", "iis"],
    "ASP.NET": ["asp.net"], ".NET": [".net framework", ".net"], "SQL Server": ["sql server"],
    "Exchange": ["exchange server", "exchange"], "Office": ["office", "outlook", "sharepoint", "word", "excel", "powerpoint"],
    "Fortinet": ["fortinet"], "Cisco": ["cisco"], "Palo Alto": ["palo alto networks", "pan-os"], "Ivanti": ["ivanti"],
    "Citrix": ["citrix", "netscaler"], "SonicWall": ["sonicwall"], "SD-WAN": ["velocloud"],
    "Linux": ["linux kernel", "linux"], "VMware": ["vmware", "esxi", "vcenter"], "Apache": ["apache"],
    "nginx": ["nginx"], "OpenSSL": ["openssl"], "OpenSSH": ["openssh"], "BIND": ["bind", "isc"],
    "Oracle": ["oracle"], "QNAP": ["qnap"], "Synology": ["synology"], "Veeam": ["veeam"],
    "PHP": ["php"], "Java": ["java", "openjdk", "graalvm"], "Node.js": ["node.js", "nodejs"], "Go": ["go", "golang"],
    "GitLab": ["gitlab"], "Atlassian": ["atlassian", "confluence", "jira"], "Chrome": ["chrome", "chromium"],
    "AI 平台": ["langflow", "litellm", "ollama", "n8n", "comfyui", "vllm", "open webui"],
}

# NVD 的 CNA（發布單位）對應產品：剛公布、還沒有 CPE 時靠這個辨識
CNA = {
    "security@php.net": "PHP", "security@golang.org": "Go", "cve@gitlab.com": "GitLab",
    "psirt@fortinet.com": "Fortinet", "psirt@cisco.com": "Cisco", "psirt@paloaltonetworks.com": "Palo Alto",
    "security-officer@isc.org": "BIND", "openssl-security@openssl.org": "OpenSSL", "secalert_us@oracle.com": "Oracle",
    "chrome-cve-admin@google.com": "Chrome", "security@qnap.com": "QNAP", "security@synology.com": "Synology",
}

# 關鍵字命中但描述含這些字 → 視為誤判（例如 npm 套件描述常寫「for Node.js」）
EXCLUDE = {
    "Node.js": [r"\bnpm\b", r"\bpackage\b", r"\bmodule\b", r"\blibrary\b", r"\bplugin\b", r"\bwrapper\b",
                r"node\.js (process|applications?|apps?|servers? built)", r"(?-i:^[a-z0-9@][\w./@-]*)\s+(before|is|prior|versions?|through|<)"],
    "Go": [r"\bgithub\.com/"],
    "PHP": [r"management system", r"sourcecodester", r"\.php\b", r"wordpress", r"\bplugin\b", r"\btheme\b"],
}

# 還沒有 CVSS 分數時，描述含這些字就先以「高」收錄，等評分後自動校正
SEVERE_WORDS = r"remote code execution|execute arbitrary (code|commands)|arbitrary code execution|command injection|authentication bypass|unauthenticated (remote )?attackers?"

# 這些 CNA 發布的多半是第三方套件（例如 GitHub 代管的 npm／Go 套件），只靠關鍵字命中時不採用
KW_BLOCK_CNA = {
    "Node.js": ["security-advisories@github.com"], "Go": ["security-advisories@github.com"],
    "PHP": ["security-advisories@github.com"], "Java": ["security-advisories@github.com"],
}
