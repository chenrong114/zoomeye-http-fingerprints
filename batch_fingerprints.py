"""
Batch collect HTTP fingerprints from ZoomEye for each pattern in patterns_table.csv.

Strategy:
  1. Build a broad ZoomEye query from the pattern's literal prefix.
  2. Fetch results in pages (up to MAX_PAGES per pattern).
  3. Extract the Server header value from each record's full header string.
  4. Apply the original regex via re.fullmatch() — only keep true matches.
  5. Stop when MAX_RESULTS matching records are collected, or pages run out.

Output: fingerprints.csv  (name, pattern, response_content)
Progress is saved to progress.json so the script can resume after interruption.
"""
import base64
import csv
import json
import os
import re
import time

import requests

API_KEY   = os.getenv("ZOOMEYE_API_KEY")
if not API_KEY:
    raise RuntimeError("ZOOMEYE_API_KEY environment variable is not set.")
API_URL   = "https://api.zoomeye.org/v2/search"

PATTERNS_CSV  = "patterns_table.csv"
OUTPUT_CSV    = "fingerprints.csv"
PROGRESS_FILE = "progress.json"

MAX_RESULTS  = 100   # desired matching records per pattern
MAX_PAGES    = 5     # max ZoomEye pages fetched per pattern (5×100 = 500 candidates)
PAGE_SIZE    = 100
DELAY        = 1.5   # seconds between requests


# ── Server header extraction ───────────────────────────────────────────────────

def extract_server_value(full_header: str) -> str:
    """Return the value of the Server: line from an HTTP response header block."""
    for line in full_header.split("\n"):
        stripped = line.strip()
        if stripped.lower().startswith("server:"):
            return stripped[7:].strip()
    return ""


# ── Query derivation (broad — used to pull candidates from ZoomEye) ────────────

def extract_literal_prefix(pattern: str) -> str:
    """Longest literal prefix before the first unescaped regex metachar."""
    p = re.sub(r"^\(\?[iIsSmMxX]*\)", "", pattern)
    i = 1 if p.startswith("^") else 0
    prefix = []
    while i < len(p):
        c = p[i]
        if c == "\\":
            if i + 1 >= len(p):
                break
            nc = p[i + 1]
            if nc.lower() in "dwstnrb":   # \d \w \s etc. → stop
                break
            if i + 2 < len(p) and p[i + 2] == "?":  # \X? → optional → stop
                break
            prefix.append(nc)
            i += 2
            continue
        if c in r".+*?[{()|$":
            break
        prefix.append(c)
        i += 1
    result = "".join(prefix).strip()
    return re.sub(r"[^a-zA-Z0-9/]+$", "", result)   # trim trailing non-word chars


def build_query(name: str, pattern: str) -> str:
    """Derive a ZoomEye http.header.server query from a regex pattern."""
    # Strip inline flags
    stripped = re.sub(r"^\(\?[iIsSmMxX]*\)", "", pattern)
    had_flag = stripped != pattern

    has_start = stripped.startswith("^")
    has_end   = stripped.endswith("$")
    inner     = stripped[1:] if has_start else stripped
    inner     = inner[:-1]   if has_end   else inner

    def is_literal(s: str) -> bool:
        i = 0
        while i < len(s):
            if s[i] == "\\":
                i += 2; continue
            if s[i] in r".+*?[{()|":
                return False
            i += 1
        return True

    # Pure exact match (no regex specials, no case-insensitive flag)
    if has_start and has_end and is_literal(inner) and not had_flag:
        value = re.sub(r"\\(.)", r"\\1", inner)
        return f'http.header.server=="{value}"'

    prefix = extract_literal_prefix(pattern)
    if prefix:
        return f'http.header.server="{prefix}"'

    # Last resort: first meaningful word from description
    fallback = re.split(r"[,(/]", name)[0].strip().split()[-1]
    return f'http.header.server="{fallback}"'


# ── ZoomEye search with regex filtering ───────────────────────────────────────

def zoomeye_search_filtered(query: str, pattern: str) -> list[str]:
    """
    Fetch ZoomEye results for `query`, filter with `pattern` via re.fullmatch,
    and return up to MAX_RESULTS full HTTP header strings.
    """
    try:
        regex = re.compile(pattern)
    except re.error as e:
        print(f"  [WARN] Invalid regex '{pattern}': {e}")
        return []

    collected: list[str] = []
    headers_http = {"API-KEY": API_KEY, "Content-Type": "application/json"}

    for page in range(1, MAX_PAGES + 1):
        qbase64 = base64.b64encode(query.encode()).decode()
        payload = {
            "qbase64": qbase64,
            "page": page,
            "pagesize": PAGE_SIZE,
            "fields": "header",
        }
        try:
            resp = requests.post(API_URL, json=payload, headers=headers_http, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"  [ERROR] page {page}: {e}")
            break

        if data.get("code") != 60000:
            print(f"  [WARN] code {data.get('code')}: {data.get('message')}")
            break

        batch = data.get("data", [])
        if not batch:
            break

        for record in batch:
            full_header = record.get("header", "")
            if not full_header:
                continue
            server_val = extract_server_value(full_header)
            if server_val and regex.fullmatch(server_val):
                collected.append(full_header)
                if len(collected) >= MAX_RESULTS:
                    return collected

        if len(batch) < PAGE_SIZE:
            break   # ZoomEye has no more pages

        if page < MAX_PAGES:
            time.sleep(0.5)   # short pause between pages of the same pattern

    return collected


# ── CSV / progress helpers ─────────────────────────────────────────────────────

def load_patterns() -> list[tuple[str, str]]:
    with open(PATTERNS_CSV, newline="", encoding="utf-8-sig") as f:
        return [(r["description"].strip(), r["pattern"].strip())
                for r in csv.DictReader(f)]

def load_progress() -> set[int]:
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE) as f:
            return set(json.load(f))
    return set()

def save_progress(done: set[int]):
    with open(PROGRESS_FILE, "w") as f:
        json.dump(sorted(done), f)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    patterns = load_patterns()
    done     = load_progress()
    total    = len(patterns)

    mode = "a" if done else "w"
    with open(OUTPUT_CSV, mode, newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        if not done:
            writer.writerow(["name", "pattern", "response_content"])

        for idx, (name, pattern) in enumerate(patterns):
            if idx in done:
                continue

            query = build_query(name, pattern)
            print(f"[{idx+1}/{total}] {name[:55]}")
            print(f"  regex  : {pattern[:70]}")
            print(f"  query  : {query}")

            results = zoomeye_search_filtered(query, pattern)

            for full_header in results:
                writer.writerow([name, pattern, full_header])
            csvfile.flush()

            print(f"  matched: {len(results)}")
            done.add(idx)
            save_progress(done)

            if idx < total - 1:
                time.sleep(DELAY)

    print(f"\nDone. Output: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
