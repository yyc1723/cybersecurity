#!/usr/bin/env bash
# 用假資料測試整個流程（不連網、不呼叫 AI），結果寫到暫存資料夾，不影響正式資料。
set -euo pipefail
cd "$(dirname "$0")/.."
TMP=$(mktemp -d)
cp -r scripts site data "$TMP/" 2>/dev/null || true
rm -f "$TMP/data/store.json"
(cd "$TMP" && RADAR_FIXTURES="$OLDPWD/tests/fixtures" GEMINI_API_KEY= python3 scripts/update.py)
python3 -c "import json,sys;d=json.load(open('$TMP/site/data/events.json'));print('事件數',len(d['events']));[print(e['sev'],e['title']) for e in d['events']]"
