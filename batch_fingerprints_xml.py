"""
Batch collect HTTP fingerprints from ZoomEye for XML-defined fingerprint files.

Handles: http_cookies.xml, http_wwwauth.xml, http_xpoweredby.xml

Verified ZoomEye query format: http.header="<Header-Name>: <search_term>"
  - http.header="Set-Cookie: PHPSESSID"        → ~12M results
  - http.header="WWW-Authenticate: Basic realm=Transmission" → ~960K results
  - http.header="X-Powered-By: PHP"            → ~45M results

Usage:
  python batch_fingerprints_xml.py                    # process all three files
  python batch_fingerprints_xml.py http_cookies.xml   # process one file
"""
import base64
import csv
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET

import requests

API_KEY = os.getenv("ZOOMEYE_API_KEY")
if not API_KEY:
    raise RuntimeError("ZOOMEYE_API_KEY environment variable is not set.")
API_URL = "https://api.zoomeye.org/v2/search"

MAX_RESULTS = 100
MAX_PAGES   = 5
PAGE_SIZE   = 100
DELAY       = 1.5   # seconds between patterns

# XML matches attr → (display header name for query, extraction name, output prefix)
MATCHES_CONFIG: dict[str, tuple[str, str, str]] = {
    "http_header.cookie":     ("Set-Cookie",       "set-cookie",       "cookies"),
    "http_header.wwwauth":    ("WWW-Authenticate",  "www-authenticate", "wwwauth"),
    "http_header.x-powered-by": ("X-Powered-By",   "x-powered-by",     "xpoweredby"),
}

DEFAULT_XML_FILES = ["http_cookies.xml", "http_wwwauth.xml", "http_xpoweredby.xml"]


# ── Header value extraction ────────────────────────────────────────────────────

def extract_header_values(full_header: str, header_name: str) -> list[str]:
    """Return all values for `header_name` from a raw HTTP response header block."""
    prefix = header_name.lower() + ":"
    values = []
    for line in full_header.split("\n"):
        stripped = line.strip()
        if stripped.lower().startswith(prefix):
            values.append(stripped[len(prefix):].strip())
    return values


# ── Literal prefix extraction (for pattern → search term) ─────────────────────

def extract_literal_prefix(pattern: str) -> str:
    """Longest literal prefix before the first unescaped regex metachar or quote."""
    p = re.sub(r"^\(\?[iIsSmMxX]*\)", "", pattern)
    i = 1 if p.startswith("^") else 0
    prefix = []
    while i < len(p):
        c = p[i]
        if c == "\\":
            if i + 1 >= len(p):
                break
            nc = p[i + 1]
            if nc.lower() in "dwstnrb":      # \d \w \s → stop
                break
            if i + 2 < len(p) and p[i + 2] == "?":   # \X? optional → stop
                break
            prefix.append(nc)
            i += 2
            continue
        if c in r'.+*?[{()|$"\'':   # regex metachars and quote chars → stop
            break
        prefix.append(c)
        i += 1
    result = "".join(prefix).strip()
    return re.sub(r"[^a-zA-Z0-9/_\-\.@]+$", "", result)


# ── Per-header-type search term derivation ─────────────────────────────────────

# Prefixes too generic to use as ZoomEye search terms alone
_TOO_GENERIC = {"Basic realm", "Digest realm", "Basic", "Digest", "Bearer",
                "NTLM", "Negotiate"}


def _term_from_example_cookie(example: str) -> str:
    m = re.match(r'^([A-Za-z0-9_\-\.%@]+)=', example)
    return m.group(1) if m else ""


def _term_from_example_wwwauth(example: str) -> str:
    # Extract realm value (most distinctive identifier, without surrounding quotes)
    m = re.search(r'realm="([^"]+)"', example, re.IGNORECASE)
    if m:
        realm = m.group(1).strip()
        # Return "Basic realm=<value>" so query is narrow but not quote-broken
        auth_type = re.match(r'^(Basic|Digest|Bearer)', example, re.IGNORECASE)
        prefix = (auth_type.group(1) + " ") if auth_type else ""
        return f"{prefix}realm={realm}"
    # No realm= — use the full example text stripped of quotes
    return re.sub(r'["\']', '', example)[:60].strip()


def _term_from_example_xpb(example: str) -> str:
    # e.g. "PHP/8.2.14" → "PHP/8.2"  (keep major.minor for specificity)
    return example.split()[0][:40]


def get_search_term(name: str, pattern: str,
                    header_name: str, examples: list[str]) -> str:
    """
    Derive the search term (WITHOUT the header-name prefix).
    The caller prepends e.g. "Set-Cookie: " to form the final query.
    """
    prefix = extract_literal_prefix(pattern)

    if header_name == "set-cookie":
        # Cookie name is the literal prefix up to the first regex metachar
        if prefix and prefix not in _TOO_GENERIC:
            return prefix
        for ex in examples:
            t = _term_from_example_cookie(ex)
            if t:
                return t

    elif header_name == "www-authenticate":
        # Include "Basic realm=<value>" so the query is narrow
        # Prefix from pattern (stops before `"`) is often "Basic realm=" — too generic
        if prefix and prefix not in _TOO_GENERIC:
            return prefix
        # Try examples first — they give us the actual realm value
        for ex in examples:
            t = _term_from_example_wwwauth(ex)
            if t:
                return t
        # Fall back: parse realm from the pattern itself
        m = re.search(r'realm=.{0,3}([A-Za-z][A-Za-z0-9_\- ]{2,})', pattern)
        if m:
            return f"Basic realm={m.group(1).strip()}"

    elif header_name == "x-powered-by":
        if prefix and prefix not in _TOO_GENERIC:
            return prefix
        for ex in examples:
            t = _term_from_example_xpb(ex)
            if t:
                return t

    # Universal last resort: last meaningful token from the description
    tokens = [w for w in re.split(r'[,(/\s]+', name.strip()) if w]
    return tokens[-1] if tokens else name[:20]


def build_query(name: str, pattern: str,
                header_display_name: str, header_name: str,
                examples: list[str]) -> str:
    """
    Build a ZoomEye query of the form:
        http.header="<Header-Display-Name>: <search_term>"
    """
    term = get_search_term(name, pattern, header_name, examples)
    return f'http.header="{header_display_name}: {term}"'


# ── ZoomEye search with regex post-filtering ──────────────────────────────────

def zoomeye_search_filtered(query: str, pattern: str,
                             header_name: str) -> list[str]:
    """
    Fetch ZoomEye pages for `query`, apply `pattern` via re.match against the
    extracted header value, and return up to MAX_RESULTS raw header strings.
    """
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print(f"  [WARN] Invalid regex: {e}")
        return []

    collected: list[str] = []
    http_headers = {"API-KEY": API_KEY, "Content-Type": "application/json"}

    for page in range(1, MAX_PAGES + 1):
        payload = {
            "qbase64": base64.b64encode(query.encode()).decode(),
            "page":     page,
            "pagesize": PAGE_SIZE,
            "fields":   "header",
        }
        try:
            resp = requests.post(API_URL, json=payload,
                                 headers=http_headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"  [ERROR] page {page}: {e}")
            break

        if data.get("code") != 60000:
            print(f"  [WARN] code={data.get('code')}: {data.get('message')}")
            break

        batch = data.get("data", [])
        if not batch:
            break

        for record in batch:
            full_header = record.get("header", "")
            if not full_header:
                continue
            values = extract_header_values(full_header, header_name)
            if any(regex.match(v) for v in values if v):
                collected.append(full_header)
                if len(collected) >= MAX_RESULTS:
                    return collected

        if len(batch) < PAGE_SIZE:
            break
        if page < MAX_PAGES:
            time.sleep(0.5)

    return collected


# ── XML loading ────────────────────────────────────────────────────────────────

def load_fingerprints(xml_path: str) -> tuple[str, list[tuple[str, str, list[str]]]]:
    """Parse XML → (matches_attr, [(desc, pattern, [examples]), ...])."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    matches = root.get("matches", "")
    entries = []
    for fp in root.findall("fingerprint"):
        pattern = fp.get("pattern", "").strip()
        if not pattern:
            continue
        desc_el = fp.find("description")
        desc = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
        examples = [ex.text.strip() for ex in fp.findall("example")
                    if ex.text and ex.text.strip()]
        entries.append((desc, pattern, examples))
    return matches, entries


# ── Progress helpers ───────────────────────────────────────────────────────────

def load_progress(path: str) -> set[int]:
    if os.path.exists(path):
        with open(path) as f:
            return set(json.load(f))
    return set()

def save_progress(path: str, done: set[int]) -> None:
    with open(path, "w") as f:
        json.dump(sorted(done), f)


# ── Per-file driver ────────────────────────────────────────────────────────────

def process_xml_file(xml_path: str) -> None:
    matches, fingerprints = load_fingerprints(xml_path)

    if matches not in MATCHES_CONFIG:
        print(f"[SKIP] {xml_path}: unsupported matches='{matches}'")
        return

    header_display, header_name, out_prefix = MATCHES_CONFIG[matches]
    output_csv    = f"{out_prefix}_fingerprints.csv"
    progress_file = f"{out_prefix}_progress.json"
    total         = len(fingerprints)

    print(f"\n{'='*60}")
    print(f"File   : {xml_path}  ({total} patterns)")
    print(f"Header : {header_display}")
    print(f"Output : {output_csv}")
    print(f"{'='*60}")

    done = load_progress(progress_file)
    mode = "a" if done else "w"

    with open(output_csv, mode, newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        if not done:
            writer.writerow(["name", "pattern", "response_content"])

        for idx, (name, pattern, examples) in enumerate(fingerprints):
            if idx in done:
                continue

            query = build_query(name, pattern, header_display, header_name, examples)
            print(f"\n[{idx+1}/{total}] {name[:55]}")
            print(f"  regex : {pattern[:70]}")
            print(f"  query : {query}")

            results = zoomeye_search_filtered(query, pattern, header_name)

            for full_header in results:
                writer.writerow([name, pattern, full_header])
            csvfile.flush()

            print(f"  found : {len(results)}")
            done.add(idx)
            save_progress(progress_file, done)

            if idx < total - 1:
                time.sleep(DELAY)

    print(f"\nDone: {output_csv}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    xml_files = sys.argv[1:] if len(sys.argv) > 1 else DEFAULT_XML_FILES
    for xml_file in xml_files:
        if not os.path.exists(xml_file):
            print(f"[ERROR] File not found: {xml_file}")
            continue
        process_xml_file(xml_file)


if __name__ == "__main__":
    main()
