#!/usr/bin/env python3
"""check.py — repository quality checks for the pentesting course.

Standard library only. Run from the repo root:  py scripts/check.py

Checks:
  1. Internal Markdown links resolve (relative file links, ignoring http(s)/anchors/mailto).
  2. Every lesson file under lessons/module-*/ is linked in _sidebar.md (else course.py can't
     see it), and every lesson link in _sidebar.md points to a file that exists.
  3. Every lesson has the required structural markers (prereq box, progress checkpoint).
  4. Currency: warn on lessons whose "last reviewed" date (if present) is > 18 months old.
  5. Safety: every lesson that reads like offensive content restates the lab/authorization boundary.

Exit code 0 if no errors (warnings don't fail), 1 otherwise.
"""
from __future__ import annotations
import datetime as dt
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []
warnings: list[str] = []

def err(m): errors.append(m)
def warn(m): warnings.append(m)

MD_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

def check_links() -> None:
    for md in ROOT.rglob("*.md"):
        if any(p in md.parts for p in (".git", "node_modules")):
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        for m in MD_LINK.finditer(text):
            target = m.group(1).strip()
            if target.startswith(("http://", "https://", "mailto:", "#", "data:")):
                continue
            target = target.split("#", 1)[0].split("?", 1)[0]
            if not target or target.startswith("$"):
                continue
            dest = (md.parent / target).resolve()
            if not dest.exists():
                err(f"broken link in {md.relative_to(ROOT)} -> {target}")

def lesson_files() -> list[Path]:
    return sorted(ROOT.glob("lessons/module-*/lesson-*.md"))

def check_sidebar() -> None:
    sidebar = ROOT / "_sidebar.md"
    linked = set(re.findall(r"\(lessons/module-\d+/lesson-\d+\.md\)", sidebar.read_text(encoding="utf-8")))
    linked = {s[1:-1] for s in linked}
    for lf in lesson_files():
        rel = lf.relative_to(ROOT).as_posix()
        if rel not in linked:
            err(f"lesson not linked in _sidebar.md (course.py won't track it): {rel}")

def check_structure() -> None:
    for lf in lesson_files():
        t = lf.read_text(encoding="utf-8", errors="replace")
        rel = lf.relative_to(ROOT).as_posix()
        if 'class="prereq"' not in t:
            warn(f"missing .prereq box: {rel}")
        if "course.py complete" not in t:
            err(f"missing progress checkpoint: {rel}")

OFFENSIVE_HINT = re.compile(r"\b(exploit|payload|privilege escalation|reverse shell|inject|attack)\b", re.I)
SAFETY_HINT = re.compile(r"lab target|isolated|authoriz|LAB ONLY", re.I)

def check_safety() -> None:
    for lf in lesson_files():
        t = lf.read_text(encoding="utf-8", errors="replace")
        if OFFENSIVE_HINT.search(t) and not SAFETY_HINT.search(t):
            warn(f"offensive content without a visible lab/authorization boundary: {lf.relative_to(ROOT).as_posix()}")

DATE = re.compile(r"[Ll]ast[- ]reviewed:?\s*(\d{4})-(\d{2})", )

def check_currency() -> None:
    cutoff = dt.date.today() - dt.timedelta(days=548)  # ~18 months
    for md in ROOT.rglob("*.md"):
        if ".git" in md.parts:
            continue
        m = DATE.search(md.read_text(encoding="utf-8", errors="replace"))
        if m:
            d = dt.date(int(m.group(1)), int(m.group(2)), 1)
            if d < cutoff:
                warn(f"stale (last reviewed {m.group(1)}-{m.group(2)}): {md.relative_to(ROOT).as_posix()}")

def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    check_links(); check_sidebar(); check_structure(); check_safety(); check_currency()
    n_les = len(lesson_files())
    print(f"Checked {n_les} lessons.")
    for w in warnings:
        print(f"  WARN: {w}")
    for e in errors:
        print(f"  ERROR: {e}")
    print(f"\n{len(errors)} error(s), {len(warnings)} warning(s).")
    sys.exit(1 if errors else 0)

if __name__ == "__main__":
    main()
