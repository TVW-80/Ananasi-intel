#!/usr/bin/env python3
"""Daily refresh for the Anansi AI Security dashboard.

1. Pulls the CISA Known Exploited Vulnerabilities (KEV) catalog and keeps only
   AI/ML entries (MLflow, Ray, Langflow, Kubeflow, ...).
2. New matches become advisories, enriched from the official CVE record
   (CVSS, affected versions, title). Existing advisories are upgraded to
   "kev" status when CISA confirms exploitation. Curated text is never
   overwritten.
3. Adds an EPSS exploit-likelihood score (FIRST.org) to every advisory.
4. Optionally (SHODAN_API_KEY set) counts internet-exposed AI/ML services
   with Shodan's count endpoint. Only totals and country tallies are kept —
   never IP addresses or hostnames.
5. Records what changed in a rolling 30-day history, then rebuilds index.html.

Standard library only. Usage:
    python3 scripts/update_intel.py                 # live run
    python3 scripts/update_intel.py --kev-file kev.json --epss-file epss.json
    python3 scripts/update_intel.py --dry-run
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "ai-security.json"

USER_AGENT = "Anansi-AI-Security/1.0 (+https://github.com/TVW-80/Ananasi-intel)"
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Official CISA mirror on GitHub, used if the primary feed is unreachable.
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_RECORD_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve}.json"
KEV_LINK = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve}"

# Matched against vendor + product + vulnerability name (not the long
# description, which mentions "AI" far too loosely).
AI_ML_PATTERN = re.compile(
    r"\b("
    r"mlflow|ray-project|langflow|langchain|langsmith|llama[\w.-]*|ollama|vllm|"
    r"triton inference|torchserve|tensorflow|pytorch|hugging ?face|kubeflow|"
    r"jupyter\w*|gradio|comfyui|open ?webui|anythingllm|h2o|clearml|bentoml|"
    r"nemo|litellm|flowise|dify|ai|llm|machine learning|artificial intelligence"
    r")\b",
    re.IGNORECASE,
)

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")


# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #
def fetch_json(url: str, retries: int = 2, timeout: int = 60, label: str | None = None):
    """GET JSON. `label` replaces the URL in error messages (use it when the
    URL carries a secret, so keys never reach public Action logs)."""
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last = exc
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
    detail = getattr(last, "code", None) or getattr(last, "reason", None) or type(last).__name__
    if label is None:
        detail = last
    raise RuntimeError(f"{label or url}: {detail}")


def load_kev(kev_file: str | None) -> dict:
    if kev_file:
        return json.loads(pathlib.Path(kev_file).read_text())
    errors = []
    for url in KEV_URLS:
        try:
            return fetch_json(url)
        except RuntimeError as exc:
            errors.append(str(exc))
            log(f"warn: KEV source failed, trying next — {exc}")
    raise RuntimeError("all KEV sources failed: " + " | ".join(errors))


def load_epss(cves: list[str], epss_file: str | None) -> dict[str, dict]:
    if epss_file:
        rows = json.loads(pathlib.Path(epss_file).read_text()).get("data", [])
    else:
        rows = []
        for i in range(0, len(cves), 50):  # keep URLs short
            query = urllib.parse.urlencode({"cve": ",".join(cves[i : i + 50])})
            rows += fetch_json(f"{EPSS_URL}?{query}").get("data", [])
    out = {}
    for row in rows:
        try:
            out[row["cve"]] = {
                "score": round(float(row["epss"]), 5),
                "percentile": round(float(row["percentile"]), 5),
                "date": row.get("date"),
            }
        except (KeyError, TypeError, ValueError):
            continue
    return out


def load_cve_record(cve: str) -> dict | None:
    m = CVE_RE.match(cve)
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    url = CVE_RECORD_URL.format(year=year, bucket=int(num) // 1000, cve=cve)
    try:
        return fetch_json(url, retries=1, timeout=30)
    except RuntimeError as exc:
        log(f"warn: no CVE record for {cve} — {exc}")
        return None


SHODAN_COUNT_URL = "https://api.shodan.io/shodan/host/count"

# Aggregate exposure queries. Counts only: the count endpoint returns totals
# and facets, never host records, and it does not use Shodan query credits.
EXPOSURE_QUERIES = [
    {"id": "ray", "label": "Ray dashboards", "query": 'http.title:"Ray Dashboard"'},
    {"id": "mlflow", "label": "MLflow servers", "query": 'http.title:"MLflow"'},
    {"id": "ollama", "label": "Ollama APIs", "query": '"Ollama is running"'},
    {"id": "langflow", "label": "Langflow instances", "query": 'http.title:"Langflow"'},
    {"id": "kubeflow", "label": "Kubeflow dashboards", "query": 'http.title:"Kubeflow Central Dashboard"'},
]


def load_exposure(previous: dict | None, shodan_file: str | None, today: str) -> dict | None:
    """Returns the exposure block, or None when Shodan isn't configured."""
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    canned = json.loads(pathlib.Path(shodan_file).read_text()) if shodan_file else None
    if not key and canned is None:
        return previous  # not configured: keep whatever was there (or nothing)
    old = {i["id"]: i for i in (previous or {}).get("items", [])}
    items, failures = [], 0
    for q in EXPOSURE_QUERIES:
        try:
            if canned is not None:
                body = canned[q["id"]]
            else:
                params = urllib.parse.urlencode({"key": key, "query": q["query"], "facets": "country:3"})
                body = fetch_json(f"{SHODAN_COUNT_URL}?{params}", retries=1, timeout=30, label=f"Shodan count ({q['id']})")
            total = int(body["total"])
            countries = [
                {"value": str(c["value"]), "count": int(c["count"])}
                for c in (body.get("facets") or {}).get("country", [])[:3]
            ]
        except (RuntimeError, KeyError, TypeError, ValueError) as exc:
            failures += 1
            log(f"warn: exposure count failed for {q['id']} — {exc}")
            if q["id"] in old:
                items.append({**old[q["id"]], "stale": True})
            continue
        prev = old.get(q["id"], {})
        items.append({
            **q,
            "total": total,
            "previous": prev.get("total") if prev.get("date") != today else prev.get("previous"),
            "topCountries": countries,
            "date": today,
        })
        time.sleep(1)  # Shodan asks for at most 1 request per second
    if not items:
        return previous
    return {"source": "Shodan", "date": today, "items": items, "partial": failures > 0}


# --------------------------------------------------------------------------- #
# Mapping KEV + CVE record -> dashboard advisory
# --------------------------------------------------------------------------- #
def is_ai_ml(entry: dict) -> bool:
    text = " ".join([entry.get("vendorProject", ""), entry.get("product", ""), entry.get("vulnerabilityName", "")])
    return bool(AI_ML_PATTERN.search(text))


def cvss_from_record(record: dict | None):
    """Best available CVSS: CNA first, then ADP; newest CVSS version first."""
    if not record:
        return None
    containers = record.get("containers", {})
    blocks = [containers.get("cna", {})] + list(containers.get("adp", []))
    for block in blocks:
        for key, version in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0")):
            for metric in block.get("metrics", []):
                data = metric.get(key)
                if data and isinstance(data.get("baseScore"), (int, float)):
                    sev = str(data.get("baseSeverity", "")).title() or severity_for(data["baseScore"])
                    return {"cvss": float(data["baseScore"]), "cvssVersion": version, "severity": sev}
    return None


def severity_for(score: float) -> str:
    return "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"


def versions_from_record(record: dict | None) -> tuple[str, str]:
    """Return (affected, fixed) strings from the CVE record, or advisory fallbacks."""
    fallback = ("See vendor advisory", "See vendor advisory")
    if not record:
        return fallback
    affected, fixed = [], []
    for item in record.get("containers", {}).get("cna", {}).get("affected", []):
        for v in item.get("versions", []):
            if v.get("status") != "affected":
                continue
            start = v.get("version", "")
            start = "" if start in ("0", "*", "n/a", "unspecified") else start
            if v.get("lessThan"):
                affected.append(f"{start}–<{v['lessThan']}" if start else f"< {v['lessThan']}")
                fixed.append(f"{v['lessThan']}+")
            elif v.get("lessThanOrEqual"):
                affected.append(f"{start}–{v['lessThanOrEqual']}" if start else f"≤ {v['lessThanOrEqual']}")
            elif start:
                affected.append(start)
                # Some CNAs put the whole range in the version text, e.g. "< 1.9.0".
                m = re.search(r"(?<![<>=≤])<\s*v?([0-9][\w.]*)", start)
                if m and "=" not in start[m.start() : m.start() + 2]:
                    fixed.append(f"{m.group(1)}+")
    dedupe = lambda xs: list(dict.fromkeys(xs))
    affected, fixed = dedupe(affected)[:3], dedupe(fixed)[:3]
    return (" / ".join(affected) or fallback[0], " / ".join(fixed) or fallback[1])


def title_for(kev: dict, record: dict | None) -> str:
    cna_title = (record or {}).get("containers", {}).get("cna", {}).get("title")
    if cna_title and len(cna_title) <= 100:
        # The product is shown separately, so drop a leading "Product:",
        # "Product has" or "Product <= 1.2.3" from the CNA title.
        product = re.escape(kev.get("product", ""))
        cleaned = re.sub(
            rf"^{product}\s*(?:(?:[<>]=?|≤)\s*[\w.]+\s*)?(?::\s*|has\s+|-\s+)?", "", cna_title, flags=re.IGNORECASE
        ).strip()
        cleaned = cleaned[:1].upper() + cleaned[1:]
        return cleaned or cna_title
    name = kev.get("vulnerabilityName", "")
    for prefix in (kev.get("vendorProject", ""), kev.get("product", "")):
        if prefix and name.lower().startswith(prefix.lower()):
            name = name[len(prefix):].strip()
    return re.sub(r"\s*Vulnerability$", "", name) or "Exploited vulnerability"


def sources_from_notes(cve: str, notes: str) -> list[dict]:
    sources, seen = [], set()
    for url in re.findall(r"https?://[^\s;]+", notes or ""):
        url = url.rstrip(".,)")
        host = urllib.parse.urlparse(url).netloc.lower()
        if url in seen or ("cisa.gov" in host and "directives" in url):
            continue  # skip BOD boilerplate links
        seen.add(url)
        if "nvd.nist.gov" in host:
            label = "NVD"
        elif "github.com" in host and "/security/advisories/" in url:
            label = "Maintainer advisory"
        elif "github.com" in host:
            label = "GitHub"
        else:
            label = "Vendor advisory"
        sources.append({"label": label, "url": url})
    sources.append({"label": "CISA KEV", "url": KEV_LINK.format(cve=cve)})
    return sources


def advisory_from_kev(kev: dict, record: dict | None, today: str) -> dict:
    cve = kev["cveID"]
    product = kev.get("product") or kev.get("vendorProject") or "Unknown product"
    scores = cvss_from_record(record) or {"cvss": None, "cvssVersion": None, "severity": "Unscored"}
    affected, fixed = versions_from_record(record)
    published = ((record or {}).get("cveMetadata", {}).get("datePublished") or kev["dateAdded"])[:10]
    ransomware = kev.get("knownRansomwareCampaignUse") == "Known"
    exploitation = f"Added to CISA KEV on {fmt_date(kev['dateAdded'])} — confirmed in-the-wild exploitation."
    if ransomware:
        exploitation += " Known use in ransomware campaigns."
    return {
        "id": cve,
        "product": product,
        "title": title_for(kev, record),
        "status": "kev",
        "severity": scores["severity"],
        "cvss": scores["cvss"],
        "cvssVersion": scores["cvssVersion"],
        "published": published,
        "affected": affected,
        "fixed": fixed,
        "summary": kev.get("shortDescription", "").strip(),
        "exposedIf": f"An affected {product} release is deployed and reachable by untrusted users or networks.",
        "doNow": "Apply the vendor fix or mitigations from the advisory. If none are available, remove internet exposure or discontinue use (CISA guidance).",
        "lookFor": "Indicators listed in the vendor advisory, plus unexpected processes, requests, or configuration changes on the service.",
        "exploitation": exploitation,
        "kevAdded": kev["dateAdded"],
        "sources": sources_from_notes(cve, kev.get("notes", "")),
        "auto": True,
        "addedAt": today,
    }


# --------------------------------------------------------------------------- #
# Merge
# --------------------------------------------------------------------------- #
def merge(data: dict, kev_catalog: dict, epss: dict[str, dict] | None, today: str, fetch_records=True) -> list[dict]:
    """Mutates data in place; returns the list of change entries."""
    changes = []
    by_id = {a["id"]: a for a in data["advisories"]}
    matches = [k for k in kev_catalog.get("vulnerabilities", []) if is_ai_ml(k)]

    for kev in sorted(matches, key=lambda k: k["dateAdded"]):
        cve = kev["cveID"]
        existing = by_id.get(cve)
        if existing:
            existing["kevAdded"] = kev["dateAdded"]
            if existing.get("status") != "kev":
                existing["status"] = "kev"
                existing["exploitation"] = (
                    f"Added to CISA KEV on {fmt_date(kev['dateAdded'])} — confirmed in-the-wild exploitation."
                )
                if not any(s["label"] == "CISA KEV" for s in existing.get("sources", [])):
                    existing.setdefault("sources", []).append({"label": "CISA KEV", "url": KEV_LINK.format(cve=cve)})
                changes.append(change(today, cve, f"{existing['product']}: now confirmed exploited (CISA KEV)"))
            continue
        record = load_cve_record(cve) if fetch_records else None
        adv = advisory_from_kev(kev, record, today)
        data["advisories"].append(adv)
        by_id[cve] = adv
        changes.append(change(today, cve, f"{adv['product']}: {adv['title']} — added from CISA KEV"))

    if epss is not None:
        for adv in data["advisories"]:
            if adv["id"] in epss:
                adv["epss"] = epss[adv["id"]]

    meta = data["meta"]
    history_days = int(meta.get("historyDays", 30))
    cutoff = (dt.date.fromisoformat(today) - dt.timedelta(days=history_days)).isoformat()
    meta["changes"] = [c for c in changes + meta.get("changes", []) if c["date"] >= cutoff]
    meta["kevCatalogVersion"] = kev_catalog.get("catalogVersion")
    return changes


def change(date: str, cve: str, text: str) -> dict:
    return {"date": date, "id": cve, "text": text}


def fmt_date(iso: str) -> str:
    d = dt.date.fromisoformat(iso[:10])
    return f"{d:%b} {d.day}, {d.year}"


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kev-file", help="Use a local KEV JSON file instead of downloading")
    ap.add_argument("--epss-file", help="Use a local EPSS API response instead of downloading")
    ap.add_argument("--no-cve-records", action="store_true", help="Skip CVE record enrichment")
    ap.add_argument("--shodan-file", help="Use canned Shodan count responses ({id: response}) for testing")
    ap.add_argument("--dry-run", action="store_true", help="Print changes without writing files")
    args = ap.parse_args()

    data = json.loads(DATA_FILE.read_text())
    now = dt.datetime.now(dt.timezone.utc)
    today = now.date().isoformat()

    try:
        kev = load_kev(args.kev_file)
    except RuntimeError as exc:
        log(f"error: {exc}")
        return 1  # keep the published data untouched

    health = "Healthy"
    ids_after_kev = sorted({a["id"] for a in data["advisories"]} | {k["cveID"] for k in kev.get("vulnerabilities", []) if is_ai_ml(k)})
    try:
        epss = load_epss(ids_after_kev, args.epss_file)
    except RuntimeError as exc:
        log(f"warn: EPSS unavailable, keeping previous scores — {exc}")
        epss, health = None, "Degraded (EPSS unavailable)"

    changes = merge(data, kev, epss, today, fetch_records=not args.no_cve_records)

    exposure = load_exposure(data.get("exposure"), args.shodan_file, today)
    if exposure is not None:
        data["exposure"] = exposure
        if exposure.get("partial") and health == "Healthy":
            health = "Degraded (some exposure counts unavailable)"
    data["meta"]["lastRefresh"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    data["meta"]["health"] = health

    for c in changes:
        print(f"+ {c['id']}: {c['text']}")
    print(f"{len(changes)} change(s); {len(data['advisories'])} advisories; EPSS {'ok' if epss is not None else 'skipped'}")

    if args.dry_run:
        return 0
    DATA_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    subprocess.run([sys.executable, str(ROOT / "build.py")], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
