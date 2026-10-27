"""執行入口：python scripts/update.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from radar.pipeline import run  # noqa: E402

if __name__ == "__main__":
    changed = run()
    # 讓 GitHub Actions 知道資料有沒有變（決定要不要 commit）
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")
