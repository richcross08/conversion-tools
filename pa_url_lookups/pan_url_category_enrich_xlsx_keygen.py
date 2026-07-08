#!/usr/bin/env python3
"""
Enrich an IronPort URL export with Palo Alto URL category/action data.

What this script does:
  1. Reads a proxy CSV that contains URLs/domains and the IronPort category.
  2. Reads ironport-category-actions.csv to map IronPort category -> IronPort action.
  3. Calls the PAN-OS URL test API for each URL/domain.
  4. Parses ONLY the Cloud DB return from PAN-OS.
  5. Reads palo-category-actions.json to map Palo Alto returned categories -> Palo Alto action.
  6. Writes one enriched XLSX row per input row by default.
     Use --skip-cached-output to write only URLs that were not already in cache. The workbook also includes Proxy Source, IronPort Actions, Palo Actions, and Cache tabs.

No IronPort category is compared to any Palo Alto category.

Enriched URLs sheet columns:
  URL, Ironport category, Ironport action, palo alto category, palo alto action

With --include-extra:
  Adds palo alto db url, lookup status, api raw result.

Authentication options:
  1. Existing behavior: set PANOS_API_KEY or pass --api-key.
  2. New behavior: pass --username and either --password, --password-env, or --prompt-password.
     The script will call the PAN-OS keygen API and use the returned key for URL lookups.

Example with existing API key:
  export PANOS_API_KEY='your-api-key'

  python3 pan_url_category_enrich.py \
    --firewall 100.50.81.108:4443 \
    --proxy-csv "Proxy_top5000_2026_04.csv" \
    --ironport-actions-csv "ironport-category-actions.csv" \
    --palo-actions-json "palo-category-actions.json" \
    --output "url_categories_enriched.xlsx" \
    --cache "pan_url_category_cache.json" \
    --include-extra \
    --skip-cached-output \
    --no-verify

Example with keygen using a password prompt:
  python3 pan_url_category_enrich.py \
    --firewall 100.50.81.108:4443 \
    --username wei-admin \
    --prompt-password \
    --proxy-csv "Proxy_top5000_2026_04.csv" \
    --ironport-actions-csv "ironport-category-actions.csv" \
    --palo-actions-json "palo-category-actions.json" \
    --output "url_categories_enriched.xlsx" \
    --cache "pan_url_category_cache.json" \
    --include-extra \
    --no-verify
"""

from __future__ import annotations

import argparse
import csv
import getpass
import html
import json
import os
import re
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import requests
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: requests. Install it with: python3 -m pip install requests"
    ) from exc


DEFAULT_OUTPUT_XLSX = "url_categories_enriched.xlsx"
DEFAULT_CACHE = "pan_url_category_cache.json"

# Used only if PAN-OS returns more than one Palo Alto category/action.
# Your uploaded action file currently uses Alert, Block, and Continue.
ACTION_SEVERITY = {
    "unknown": -1,
    "allow": 0,
    "alert": 1,
    "continue": 2,
    "override": 3,
    "block": 4,
}


@dataclass(frozen=True)
class CloudDbResult:
    db_url: str
    categories: Tuple[str, ...]  # e.g. ("content-delivery-networks", "low-risk")
    raw_result: str
    status: str


def normalize_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").strip().lower())


def normalize_key(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip()).casefold()


def normalize_category(value: str) -> str:
    return (value or "").strip().lower()


def find_column(fieldnames: Sequence[str], candidates: Sequence[str], required: bool = True) -> str:
    normalized = {normalize_header(name): name for name in fieldnames or []}
    for candidate in candidates:
        key = normalize_header(candidate)
        if key in normalized:
            return normalized[key]
    if required:
        raise ValueError(
            f"Could not find required column. Tried: {', '.join(candidates)}. "
            f"Available columns: {', '.join(fieldnames or [])}"
        )
    return ""


def iter_result_text(node: Optional[ET.Element]) -> str:
    if node is None:
        return ""
    # Preserve enough whitespace to keep separate lines/tokens readable.
    return "\n".join(t.strip() for t in node.itertext() if t and t.strip())


def clean_url_for_test(value: str, add_scheme: Optional[str]) -> str:
    url = (value or "").strip().strip('"').strip("'")
    if not url:
        return ""
    if add_scheme and not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"{add_scheme}://{url}"
    return url


def cache_key_for_url(url: str) -> str:
    """
    Stable cache key for repeated URLs. This keeps the exact host/path intent,
    but normalizes hostname casing and trailing slash noise.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        return ""

    parsed = urllib.parse.urlparse(cleaned if "://" in cleaned else f"//{cleaned}", scheme="")
    if parsed.netloc:
        host = parsed.netloc.lower()
        path = parsed.path.rstrip("/")
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return f"{host}{path}"
    return cleaned.lower().rstrip("/")


def read_ironport_actions(path: Path) -> Dict[str, str]:
    """
    Reads ironport-category-actions.csv:
      Category,IronPort Action
    """
    actions: Dict[str, str] = {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"No headers found in IronPort actions CSV: {path}")

        category_col = find_column(reader.fieldnames, ["Category", "IronPort Category", "Ironport category"])
        action_col = find_column(reader.fieldnames, ["IronPort Action", "Ironport action", "Action"])

        for row in reader:
            category = (row.get(category_col) or "").strip()
            action = (row.get(action_col) or "").strip()
            if category:
                actions[normalize_key(category)] = action or "unknown"

    return actions


def read_palo_actions(path: Path) -> Dict[str, str]:
    """
    Reads palo-category-actions.json:
      [
        {"category": "content-delivery-networks", "recommended_action": "Alert"},
        ...
      ]
    """
    with path.open(encoding="utf-8-sig") as f:
        data = json.load(f)

    actions: Dict[str, str] = {}

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            category = item.get("category") or item.get("name") or item.get("url_category")
            action = (
                item.get("recommended_action")
                or item.get("action")
                or item.get("recommendedAction")
            )
            if category:
                actions[normalize_category(str(category))] = str(action).strip() if action else "unknown"
    elif isinstance(data, dict):
        # Also allow {"content-delivery-networks": "Alert"} if you ever convert the file.
        for category, action in data.items():
            actions[normalize_category(str(category))] = str(action).strip() if action else "unknown"
    else:
        raise ValueError(f"Unsupported Palo Alto actions JSON format: {path}")

    return actions


def parse_panos_cloud_db_from_raw(raw_result: str) -> CloudDbResult:
    """
    Parse ONLY the Cloud DB return from PAN-OS.

    Handles both of these PAN-OS API result shapes:

      example.com content-delivery-networks low-risk (Cloud db)
      cthrt11ws003 private-ip-addresses (Cloud db)

    Returns categories:
      ("content-delivery-networks", "low-risk")
      ("private-ip-addresses",)

    It does not tokenize the Base DB text, mlav flags, expires text, or echoed URL.
    """
    raw = html.unescape(raw_result or "")
    raw = re.sub(r"\r\n?", "\n", raw).strip()

    if not raw:
        return CloudDbResult("", tuple(), raw, "empty-result")

    # API format. Capture the Cloud DB segment directly, allowing one or more
    # category/risk tokens after the returned URL. Some categories, such as
    # private-ip-addresses, are returned without a separate risk token:
    #   cthrt11ws003 private-ip-addresses (Cloud db)
    # Other results include both category and risk:
    #   pghub.io content-delivery-networks low-risk (Cloud db)
    cloud_matches = list(
        re.finditer(
            r"(?P<cloud>[^\n\r<>]*?)\s*\(Cloud\s+db\)",
            raw,
            flags=re.IGNORECASE,
        )
    )
    if cloud_matches:
        cloud_text = cloud_matches[-1].group("cloud").strip()
        parts = [p.strip() for p in cloud_text.split() if p.strip()]
        if len(parts) >= 2:
            db_url = parts[0]
            cats = tuple(normalize_category(p) for p in parts[1:] if normalize_category(p))
            if cats:
                return CloudDbResult(db_url, cats, raw, "success")

    # CLI url-info-cloud / batch-style fallback:
    #   blackrock.com,9,5,stock-advice-and-tools,low-risk
    # Last two comma-separated tokens are category and risk when five fields exist.
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    for line in reversed(lines):
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 5:
            primary = normalize_category(parts[-2])
            risk = normalize_category(parts[-1])
            db_url = parts[0]
            if re.fullmatch(r"[a-z0-9-]+", primary) and re.fullmatch(r"[a-z0-9-]+", risk):
                return CloudDbResult(db_url, (primary, risk), raw, "success")

    return CloudDbResult("", tuple(), raw, "parse-no-cloud-db-category")

def parse_panos_response_xml(response_xml: str) -> CloudDbResult:
    """
    Parse a full PAN-OS XML API response.
    """
    try:
        root = ET.fromstring(response_xml)
    except ET.ParseError as exc:
        return CloudDbResult("", tuple(), response_xml[:1000], f"xml-parse-error: {exc}")

    status = root.attrib.get("status", "").lower() or "unknown"
    result_node = root.find("result")
    raw_result = iter_result_text(result_node)

    if status != "success":
        msg = raw_result or iter_result_text(root.find("msg")) or response_xml[:1000]
        return CloudDbResult("", tuple(), msg, f"api-{status}")

    parsed = parse_panos_cloud_db_from_raw(raw_result)
    return parsed


def choose_palo_action(categories: Sequence[str], palo_actions: Dict[str, str]) -> str:
    """
    Map Palo Alto returned category/risk tokens to the configured Palo Alto action file.

    Example:
      categories: ["content-delivery-networks", "low-risk"]
      palo-category-actions.json:
        content-delivery-networks -> Alert
        low-risk -> Alert
      output action: Alert

    If no returned category exists in the JSON, output unknown.
    If multiple returned categories have different known actions, use the most restrictive.
    """
    found: List[str] = []
    for category in categories:
        action = palo_actions.get(normalize_category(category))
        if action and action.strip():
            found.append(action.strip())

    if not found:
        return "unknown"

    # Remove duplicate actions while preserving case from the file.
    unique = []
    seen = set()
    for action in found:
        key = action.strip().lower()
        if key not in seen:
            seen.add(key)
            unique.append(action.strip())

    if len(unique) == 1:
        return unique[0]

    return max(unique, key=lambda a: ACTION_SEVERITY.get(a.strip().lower(), -1))


def panos_test_url(
    firewall: str,
    api_key: str,
    url: str,
    timeout: float,
    verify: bool,
    retries: int,
    retry_sleep: float,
) -> CloudDbResult:
    endpoint = f"https://{firewall.rstrip('/')}/api/"
    cmd = f"<test><url>{html.escape(url, quote=False)}</url></test>"
    headers = {"X-PAN-KEY": api_key}
    params = {"type": "op", "cmd": cmd}

    last_error = ""
    for attempt in range(1, retries + 2):
        try:
            response = requests.post(
                endpoint,
                params=params,
                headers=headers,
                timeout=timeout,
                verify=verify,
            )
            response.raise_for_status()
            return parse_panos_response_xml(response.text)
        except requests.RequestException as exc:
            last_error = str(exc)
            if attempt <= retries:
                time.sleep(retry_sleep * attempt)
            else:
                return CloudDbResult("", tuple(), last_error, "request-error")

    return CloudDbResult("", tuple(), last_error, "request-error")


def panos_keygen(
    firewall: str,
    username: str,
    password: str,
    timeout: float,
    verify: bool,
    retries: int,
    retry_sleep: float,
) -> str:
    """Generate a PAN-OS XML API key using the keygen API.

    Existing --api-key / PANOS_API_KEY behavior is unchanged. This function is
    only used when no API key is supplied and --username plus a password source
    are provided. requests handles special-character URL encoding safely.
    """
    endpoint = f"https://{firewall.rstrip('/')}/api/"
    data = {"type": "keygen", "user": username, "password": password}

    last_error = ""
    for attempt in range(1, retries + 2):
        try:
            response = requests.post(
                endpoint,
                data=data,
                timeout=timeout,
                verify=verify,
            )
            response.raise_for_status()

            try:
                root = ET.fromstring(response.text)
            except ET.ParseError as exc:
                raise RuntimeError(f"Keygen XML parse error: {exc}; response={response.text[:500]}") from exc

            status = root.attrib.get("status", "").lower()
            if status != "success":
                msg = iter_result_text(root.find("msg")) or iter_result_text(root.find("result")) or response.text[:500]
                raise RuntimeError(f"Keygen failed with status={status or 'unknown'}: {msg}")

            key_node = root.find("./result/key")
            api_key = (key_node.text or "").strip() if key_node is not None else ""
            if not api_key:
                raise RuntimeError(f"Keygen succeeded but no <key> was returned: {response.text[:500]}")
            return api_key
        except (requests.RequestException, RuntimeError) as exc:
            last_error = str(exc)
            if attempt <= retries:
                time.sleep(retry_sleep * attempt)
            else:
                raise SystemExit(last_error) from exc

    raise SystemExit(last_error or "PAN-OS keygen failed")


def load_cache(cache_file: Optional[Path]) -> Dict[str, dict]:
    if not cache_file or not cache_file.exists():
        return {}
    try:
        with cache_file.open(encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_cache(cache_file: Optional[Path], cache: Dict[str, dict]) -> None:
    if not cache_file:
        return
    tmp = cache_file.with_suffix(cache_file.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)
    tmp.replace(cache_file)


def count_csv_rows(path: Path) -> int:
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        return sum(1 for _ in reader)


def progress_line(done: int, total: int, start: float, status: str, url: str) -> str:
    elapsed = max(time.time() - start, 0.001)
    rate = done / elapsed
    remaining = total - done
    eta = int(remaining / rate) if rate > 0 else 0
    pct = (done / total * 100) if total else 100.0
    return f"[{done}/{total} | {pct:6.2f}% | elapsed {int(elapsed)}s | ETA {eta}s] {status}: {url}"




# ---------- XLSX writer helpers ----------
# This script writes XLSX files directly with the Python standard library so the
# only third-party runtime dependency remains requests.

MAX_EXCEL_CELL_CHARS = 32767
MAX_EXCEL_ROWS = 1048576
MAX_EXCEL_COLS = 16384


def xml_clean(value: object) -> str:
    """Return a string safe for XML/Excel cells."""
    if value is None:
        return ""
    text = str(value)
    # Excel cells cannot exceed 32,767 characters. Preserve the beginning and
    # make truncation obvious for very large raw API results.
    if len(text) > MAX_EXCEL_CELL_CHARS:
        text = text[: MAX_EXCEL_CELL_CHARS - 20] + "... [truncated]"
    # Remove characters illegal in XML 1.0.
    return re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", text)


def xml_escape(value: object) -> str:
    text = xml_clean(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def excel_col_name(index_1_based: int) -> str:
    name = ""
    while index_1_based:
        index_1_based, remainder = divmod(index_1_based - 1, 26)
        name = chr(65 + remainder) + name
    return name


def safe_sheet_name(name: str, used: set[str]) -> str:
    cleaned = re.sub(r"[\[\]:*?/\\]", " ", name).strip() or "Sheet"
    cleaned = cleaned[:31]
    candidate = cleaned
    suffix = 2
    while candidate in used:
        base = cleaned[: 31 - len(str(suffix)) - 1]
        candidate = f"{base} {suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def normalize_matrix(rows: Sequence[Sequence[object]]) -> List[List[object]]:
    matrix = [list(row) for row in rows]
    if not matrix:
        return [["No data"]]
    width = min(max(len(row) for row in matrix), MAX_EXCEL_COLS)
    normalized: List[List[object]] = []
    for row in matrix[:MAX_EXCEL_ROWS]:
        clipped = list(row[:width])
        if len(clipped) < width:
            clipped.extend([""] * (width - len(clipped)))
        normalized.append(clipped)
    return normalized


def sheet_xml(rows: Sequence[Sequence[object]], freeze_header: bool = True) -> str:
    matrix = normalize_matrix(rows)
    row_count = len(matrix)
    col_count = max(len(row) for row in matrix) if matrix else 1
    last_cell = f"{excel_col_name(col_count)}{row_count}"

    # Simple readable column widths. The raw result/cache columns can be wide,
    # but capped to avoid an unusable workbook.
    widths = []
    sample_rows = matrix[: min(len(matrix), 200)]
    for col_idx in range(col_count):
        max_len = max((len(xml_clean(row[col_idx])) for row in sample_rows if col_idx < len(row)), default=8)
        width = min(max(max_len + 2, 10), 60)
        widths.append(width)

    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
    ]
    if freeze_header and row_count > 1:
        parts.append(
            '<sheetViews><sheetView workbookViewId="0">'
            '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
            '<selection pane="bottomLeft"/>'
            '</sheetView></sheetViews>'
        )

    parts.append('<cols>')
    for idx, width in enumerate(widths, start=1):
        parts.append(f'<col min="{idx}" max="{idx}" width="{width}" customWidth="1"/>')
    parts.append('</cols>')

    parts.append('<sheetData>')
    for r_idx, row in enumerate(matrix, start=1):
        parts.append(f'<row r="{r_idx}">')
        for c_idx, value in enumerate(row, start=1):
            ref = f"{excel_col_name(c_idx)}{r_idx}"
            style = ' s="1"' if r_idx == 1 else ''
            value_text = xml_escape(value)
            parts.append(f'<c r="{ref}" t="inlineStr"{style}><is><t>{value_text}</t></is></c>')
        parts.append('</row>')
    parts.append('</sheetData>')
    if row_count >= 1 and col_count >= 1:
        parts.append(f'<autoFilter ref="A1:{last_cell}"/>')
    parts.append('</worksheet>')
    return ''.join(parts)


def workbook_xml(sheet_names: Sequence[str]) -> str:
    sheets_xml = []
    for idx, name in enumerate(sheet_names, start=1):
        sheets_xml.append(
            f'<sheet name="{xml_escape(name)}" sheetId="{idx}" r:id="rId{idx}"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<workbookViews><workbookView xWindow="0" yWindow="0" windowWidth="24000" windowHeight="12000"/>'
        '</workbookViews><sheets>'
        + ''.join(sheets_xml)
        + '</sheets></workbook>'
    )


def workbook_rels_xml(sheet_count: int) -> str:
    rels = []
    for idx in range(1, sheet_count + 1):
        rels.append(
            f'<Relationship Id="rId{idx}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{idx}.xml"/>'
        )
    rels.append(
        f'<Relationship Id="rId{sheet_count + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + ''.join(rels)
        + '</Relationships>'
    )


def content_types_xml(sheet_count: int) -> str:
    overrides = []
    for idx in range(1, sheet_count + 1):
        overrides.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + ''.join(overrides)
        + '</Types>'
    )


def root_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        '</Relationships>'
    )


def styles_xml() -> str:
    # Style 0: normal. Style 1: bold white text on dark header fill.
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font>'
        '<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/><family val="2"/></font>'
        '</fonts>'
        '<fills count="3">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill>'
        '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '<dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>'
        '</styleSheet>'
    )


def write_xlsx(output_path: Path, sheets: Sequence[Tuple[str, Sequence[Sequence[object]]]]) -> None:
    used: set[str] = set()
    clean_sheets = [(safe_sheet_name(name, used), normalize_matrix(rows)) for name, rows in sheets]
    sheet_names = [name for name, _ in clean_sheets]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', content_types_xml(len(clean_sheets)))
        zf.writestr('_rels/.rels', root_rels_xml())
        zf.writestr('xl/workbook.xml', workbook_xml(sheet_names))
        zf.writestr('xl/_rels/workbook.xml.rels', workbook_rels_xml(len(clean_sheets)))
        zf.writestr('xl/styles.xml', styles_xml())
        for idx, (name, rows) in enumerate(clean_sheets, start=1):
            zf.writestr(f'xl/worksheets/sheet{idx}.xml', sheet_xml(rows, freeze_header=True))


def read_csv_matrix(path: Path) -> List[List[object]]:
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        return [row for row in reader]


def palo_json_matrix(path: Path) -> List[List[object]]:
    with path.open(encoding="utf-8-sig") as f:
        data = json.load(f)
    rows: List[List[object]] = [["category", "recommended_action"]]
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                rows.append([
                    item.get("category") or item.get("name") or item.get("url_category") or "",
                    item.get("recommended_action") or item.get("action") or item.get("recommendedAction") or "unknown",
                ])
    elif isinstance(data, dict):
        for category, action in sorted(data.items(), key=lambda x: str(x[0]).lower()):
            rows.append([category, action])
    return rows


def cache_matrix(cache: Dict[str, dict]) -> List[List[object]]:
    rows: List[List[object]] = [["cache key", "palo alto db url", "palo alto category", "lookup status", "fetched_at", "api raw result"]]
    for key in sorted(cache.keys()):
        item = cache.get(key) or {}
        categories = item.get("categories") or []
        if isinstance(categories, str):
            categories_text = categories
        else:
            categories_text = "; ".join(str(c) for c in categories)
        rows.append([
            key,
            item.get("db_url", ""),
            categories_text,
            item.get("status", ""),
            item.get("fetched_at", ""),
            item.get("raw_result", ""),
        ])
    return rows

def build_output(args: argparse.Namespace) -> None:
    proxy_csv = Path(args.proxy_csv)
    ironport_actions_csv = Path(args.ironport_actions_csv)
    palo_actions_json = Path(args.palo_actions_json)
    output_xlsx = Path(args.output)
    if output_xlsx.suffix.lower() != ".xlsx":
        output_xlsx = output_xlsx.with_suffix(".xlsx")
        print(f"Output is XLSX; writing {output_xlsx}", file=sys.stderr)

    cache_file = Path(args.cache) if args.cache else None

    ironport_actions = read_ironport_actions(ironport_actions_csv)
    palo_actions = read_palo_actions(palo_actions_json)
    cache = load_cache(cache_file)

    verify = not args.no_verify
    api_key = args.api_key or os.getenv(args.api_key_env)
    if not args.dry_run and not args.firewall:
        raise SystemExit("No firewall provided. Pass --firewall or use --dry-run.")

    if not args.dry_run and not api_key:
        password = args.password or os.getenv(args.password_env)
        if args.prompt_password and not password:
            password = getpass.getpass(f"PAN-OS password for {args.username or 'admin'}: ")

        if args.username and password:
            print(f"No API key supplied; requesting PAN-OS API key for user {args.username}...", file=sys.stderr)
            api_key = panos_keygen(
                firewall=args.firewall,
                username=args.username,
                password=password,
                timeout=args.timeout,
                verify=verify,
                retries=args.retries,
                retry_sleep=args.retry_sleep,
            )
            print("PAN-OS API key generated successfully.", file=sys.stderr)
        elif args.username and not password:
            raise SystemExit(
                "Username was provided but no password was available. "
                "Pass --password, set the password env var named by --password-env, or use --prompt-password."
            )
        else:
            raise SystemExit(
                f"No API key provided. Set {args.api_key_env}, pass --api-key, "
                "or pass --username with --password/--prompt-password for keygen."
            )

    total = count_csv_rows(proxy_csv)
    print(f"Found {total} input rows in {proxy_csv}", file=sys.stderr)

    start = time.time()
    errors = 0
    written = 0
    skipped_cached = 0

    # Workbook sheets are built in memory and written once as XLSX at the end.
    enriched_headers = [
        "URL",
        "Ironport category",
        "Ironport action",
        "palo alto category",
        "palo alto action",
    ]
    if args.include_extra:
        enriched_headers.extend(["palo alto db url", "lookup status", "api raw result"])
    enriched_rows: List[List[object]] = [enriched_headers]

    with proxy_csv.open(newline="", encoding="utf-8-sig") as fin:
        reader = csv.DictReader(fin)
        if not reader.fieldnames:
            raise ValueError(f"No headers found in proxy CSV: {proxy_csv}")

        url_col = args.url_column or find_column(reader.fieldnames, ["dest", "url", "URL", "Destination"])
        ironport_category_col = args.ironport_category_column or find_column(
            reader.fieldnames,
            ["category", "Ironport category", "IronPort Category"],
        )

        for row_index, row in enumerate(reader, start=1):
            raw_url = row.get(url_col, "")
            url = clean_url_for_test(raw_url, args.add_scheme)
            key = cache_key_for_url(url)

            ironport_category = (row.get(ironport_category_col) or "").strip()
            ironport_action = ironport_actions.get(normalize_key(ironport_category), "unknown")

            result = CloudDbResult("", tuple(), "", "skipped-empty-url")

            if url:
                cached = cache.get(key)

                # Optional dedupe/net-new mode: if the normalized URL key already
                # exists in cache, do not write the row and do not call the API.
                # Because the cache is updated during the run, this also skips
                # duplicate URLs that appear later in the same input file.
                if args.skip_cached_output and cached:
                    skipped_cached += 1
                    if args.progress_every and (
                        row_index == 1 or row_index == total or row_index % args.progress_every == 0
                    ):
                        print(progress_line(row_index, total, start, "skipped-cached", url), file=sys.stderr)
                    continue

                if cached and cached.get("raw_result"):
                    # Always re-parse raw_result so old dirty cache categories cannot poison output.
                    result = parse_panos_cloud_db_from_raw(cached.get("raw_result", ""))
                    if result.status == "success":
                        result = CloudDbResult(result.db_url, result.categories, result.raw_result, "cached")
                elif cached and cached.get("categories"):
                    # Legacy cache fallback only if raw_result is missing.
                    cats = tuple(normalize_category(c) for c in cached.get("categories", []) if c)
                    result = CloudDbResult(cached.get("db_url", ""), cats, cached.get("raw_result", ""), "cached-legacy")
                elif args.dry_run:
                    result = CloudDbResult("", tuple(), "", "dry-run")
                else:
                    result = panos_test_url(
                        firewall=args.firewall,
                        api_key=api_key or "",
                        url=url,
                        timeout=args.timeout,
                        verify=verify,
                        retries=args.retries,
                        retry_sleep=args.retry_sleep,
                    )
                    cache[key] = {
                        "db_url": result.db_url,
                        "categories": list(result.categories),
                        "raw_result": result.raw_result,
                        "status": result.status,
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                    }

                    if args.sleep:
                        time.sleep(args.sleep)

            if result.status not in {"success", "cached", "cached-legacy", "dry-run"}:
                errors += 1

            palo_categories = list(result.categories)
            palo_action = choose_palo_action(palo_categories, palo_actions)

            output_row: List[object] = [
                url or raw_url,
                ironport_category,
                ironport_action,
                "; ".join(palo_categories) if palo_categories else "unknown",
                palo_action,
            ]
            if args.include_extra:
                output_row.extend([result.db_url, result.status, result.raw_result])
            enriched_rows.append(output_row)
            written += 1

            if args.cache_flush_every and row_index % args.cache_flush_every == 0:
                save_cache(cache_file, cache)

            if args.progress_every and (
                row_index == 1 or row_index == total or row_index % args.progress_every == 0
            ):
                print(progress_line(row_index, total, start, result.status, url), file=sys.stderr)

    save_cache(cache_file, cache)

    sheets = [
        ("Enriched URLs", enriched_rows),
        ("Proxy Source", read_csv_matrix(proxy_csv)),
        ("IronPort Actions", read_csv_matrix(ironport_actions_csv)),
        ("Palo Actions", palo_json_matrix(palo_actions_json)),
        ("Cache", cache_matrix(cache)),
    ]
    write_xlsx(output_xlsx, sheets)

    # Basic ZIP validation so obvious file-write issues are caught before the user opens Excel.
    with zipfile.ZipFile(output_xlsx, "r") as zf:
        bad_member = zf.testzip()
        if bad_member:
            raise RuntimeError(f"XLSX validation failed; corrupt ZIP member: {bad_member}")

    print(
        f"Wrote {output_xlsx}. Processed {total} input rows; wrote {written} enriched rows; "
        f"skipped {skipped_cached} cached rows; {errors} lookup/parse issues. "
        "Workbook tabs: Enriched URLs, Proxy Source, IronPort Actions, Palo Actions, Cache.",
        file=sys.stderr,
    )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enrich IronPort URL report with PAN-OS Cloud DB URL categories/actions."
    )
    parser.add_argument("--firewall", help="PAN-OS firewall hostname/IP, optionally with port.")
    parser.add_argument("--api-key", help="PAN-OS XML API key. Prefer the PANOS_API_KEY environment variable.")
    parser.add_argument("--api-key-env", default="PANOS_API_KEY", help="Environment variable containing the PAN-OS API key.")
    parser.add_argument("--username", help="PAN-OS admin username for keygen when no API key is supplied.")
    parser.add_argument(
        "--password",
        help=(
            "PAN-OS admin password for keygen. This works, but --prompt-password or "
            "--password-env is safer because command history can expose passwords."
        ),
    )
    parser.add_argument("--password-env", default="PANOS_PASSWORD", help="Environment variable containing the PAN-OS password for keygen.")
    parser.add_argument("--prompt-password", action="store_true", help="Prompt for the PAN-OS password instead of putting it on the command line.")

    parser.add_argument("--proxy-csv", required=True, help="Input proxy URL CSV, e.g. Proxy_top5000_2026_04.csv.")
    parser.add_argument(
        "--ironport-actions-csv",
        "--mapping-csv",
        dest="ironport_actions_csv",
        required=True,
        help="IronPort category/action CSV, e.g. ironport-category-actions.csv.",
    )
    parser.add_argument("--palo-actions-json", required=True, help="Palo Alto category/action JSON, e.g. palo-category-actions.json.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT_XLSX, help="Output XLSX workbook.")
    parser.add_argument("--cache", default=DEFAULT_CACHE, help="Lookup cache JSON. Use empty string to disable.")

    parser.add_argument("--url-column", help="Override URL/domain column in proxy CSV. Default auto-detects dest/url.")
    parser.add_argument("--ironport-category-column", help="Override IronPort category column in proxy CSV. Default auto-detects category.")
    parser.add_argument("--add-scheme", choices=["http", "https"], default=None, help="Optionally prepend scheme to bare domains.")

    parser.add_argument("--timeout", type=float, default=20.0, help="API request timeout in seconds.")
    parser.add_argument("--retries", type=int, default=2, help="Retries per URL after request failures.")
    parser.add_argument("--retry-sleep", type=float, default=2.0, help="Base sleep seconds between retries.")
    parser.add_argument("--sleep", type=float, default=0.0, help="Optional sleep between successful API calls.")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification for lab/self-signed firewall certs.")
    parser.add_argument("--dry-run", action="store_true", help="Validate input/output without calling the PAN-OS API.")
    parser.add_argument("--include-extra", action="store_true", help="Include raw API result, DB URL, and lookup status.")
    parser.add_argument(
        "--skip-cached-output",
        action="store_true",
        help=(
            "Deduplicate/net-new mode: if the normalized URL is already present in the cache, "
            "skip writing that row and do not call the API. Duplicate URLs encountered later "
            "in the same run are skipped because the cache is updated as URLs are looked up."
        ),
    )
    parser.add_argument("--progress-every", type=int, default=1, help="Print progress every N rows. Use 0 to disable.")
    parser.add_argument("--cache-flush-every", type=int, default=25, help="Write cache every N processed rows. Use 0 to write only at end.")

    args = parser.parse_args(argv)
    if args.cache == "":
        args.cache = None
    return args


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    build_output(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
