"""
feed-ingest.py — SOC Threat Intelligence Feed Ingestion Script
Fetches IOCs from configured TI feeds and writes normalised JSON output.
Usage: python feed-ingest.py --source all --output ../iocs/active/
"""
import argparse, csv, json, os, sys, hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import requests, structlog
from dotenv import load_dotenv

load_dotenv()
log = structlog.get_logger()

DEFAULT_MIN_CONFIDENCE = int(os.getenv("TI_MIN_CONFIDENCE", "50"))
DEFAULT_OUTPUT_DIR = os.getenv("TI_OUTPUT_DIR", "../iocs/active/")
REQUEST_TIMEOUT = 30
MAX_IOC_AGE_DAYS = int(os.getenv("TI_MAX_IOC_AGE_DAYS", "90"))


def _make_ioc_id(ioc_type: str, value: str) -> str:
    return hashlib.sha256(f"{ioc_type}:{value.lower().strip()}".encode()).hexdigest()[:16]


def normalise_ioc(ioc_type, value, source, confidence, tlp, tags, first_seen=None, extra=None):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": _make_ioc_id(ioc_type, value),
        "ioc_type": ioc_type,
        "value": value.strip(),
        "source": source,
        "confidence": confidence,
        "tlp": tlp,
        "tags": tags,
        "first_seen": first_seen or now,
        "ingested_at": now,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=MAX_IOC_AGE_DAYS)).isoformat(),
        **(extra or {}),
    }


def fetch_urlhaus(cfg):
    log.info("fetching_urlhaus")
    iocs = []
    try:
        resp = requests.get(cfg["url"], timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines() if not l.startswith("#")]
        for row in csv.DictReader(lines):
            if row.get("url"):
                iocs.append(normalise_ioc("url", row["url"], "abuse_ch_urlhaus",
                    cfg["confidence"], cfg["tlp"], cfg["tags"], row.get("dateadded"),
                    {"threat_type": row.get("threat_type", "")}))
            if row.get("host"):
                iocs.append(normalise_ioc("domain", row["host"], "abuse_ch_urlhaus",
                    cfg["confidence"], cfg["tlp"], cfg["tags"]))
    except Exception as e:
        log.error("urlhaus_failed", error=str(e))
    log.info("urlhaus_done", count=len(iocs))
    return iocs


def fetch_threatfox(cfg):
    log.info("fetching_threatfox")
    iocs = []
    TYPE_MAP = {"ip:port": "ip", "domain": "domain", "url": "url",
                "md5_hash": "md5_hash", "sha256_hash": "sha256_hash"}
    try:
        resp = requests.post(cfg["url"], data=cfg["body"],
                             headers={"Content-Type": "application/json"}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for entry in resp.json().get("data", []):
            val = entry.get("ioc_value", "").strip()
            ioc_type = TYPE_MAP.get(entry.get("ioc_type", "").lower(), "unknown")
            if val and ioc_type != "unknown":
                iocs.append(normalise_ioc(ioc_type, val, "abuse_ch_threatfox",
                    min(int(entry.get("confidence_level", 50)), 100),
                    cfg["tlp"], cfg["tags"], entry.get("first_seen"),
                    {"malware_family": entry.get("malware", "")}))
    except Exception as e:
        log.error("threatfox_failed", error=str(e))
    log.info("threatfox_done", count=len(iocs))
    return iocs


def fetch_cisa_kev(cfg):
    log.info("fetching_cisa_kev")
    iocs = []
    try:
        resp = requests.get(cfg["url"], timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for vuln in resp.json().get("vulnerabilities", []):
            cve = vuln.get("cveID", "").strip()
            if cve:
                iocs.append(normalise_ioc("cve", cve, "cisa_kev",
                    cfg["confidence"], cfg["tlp"], cfg["tags"], vuln.get("dateAdded"),
                    {"product": vuln.get("product", ""), "vendor": vuln.get("vendorProject", ""),
                     "patch_due_date": vuln.get("dueDate", "")}))
    except Exception as e:
        log.error("cisa_kev_failed", error=str(e))
    log.info("cisa_kev_done", count=len(iocs))
    return iocs


def fetch_otx(cfg):
    api_key = os.getenv("OTX_API_KEY", "")
    if not api_key:
        log.warning("otx_skipped", reason="OTX_API_KEY not set")
        return []
    log.info("fetching_otx")
    iocs = []
    TYPE_MAP = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "URL": "url",
                "FileHash-MD5": "md5_hash", "FileHash-SHA256": "sha256_hash", "CVE": "cve"}
    try:
        resp = requests.get(cfg["url"], headers={"X-OTX-API-KEY": api_key}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        for pulse in resp.json().get("results", []):
            for ind in pulse.get("indicators", []):
                val = ind.get("indicator", "").strip()
                t = TYPE_MAP.get(ind.get("type", ""), "unknown")
                if val and t != "unknown":
                    iocs.append(normalise_ioc(t, val, "otx_pulses", cfg["confidence"],
                        cfg["tlp"], cfg["tags"] + [pulse.get("name", "")], ind.get("created")))
    except Exception as e:
        log.error("otx_failed", error=str(e))
    log.info("otx_done", count=len(iocs))
    return iocs


FEEDS = {
    "abuse_ch_urlhaus": {"url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv", "confidence": 75, "tlp": "white", "tags": ["malware", "c2"]},
    "abuse_ch_threatfox": {"url": "https://threatfox-api.abuse.ch/api/v1/",
        "type": "json_post", "body": '{"query":"get_iocs","days":1}',
        "confidence": 80, "tlp": "white", "tags": ["malware", "c2"]},
    "cisa_kev": {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "confidence": 95, "tlp": "white", "tags": ["vulnerability", "exploited-in-wild"]},
    "otx_pulses": {"url": "https://otx.alienvault.com/api/v1/pulses/subscribed?modified_since=-1d",
        "confidence": 70, "tlp": "white", "tags": ["otx"]},
}

HANDLERS = {"abuse_ch_urlhaus": fetch_urlhaus, "abuse_ch_threatfox": fetch_threatfox,
            "cisa_kev": fetch_cisa_kev, "otx_pulses": fetch_otx}


def deduplicate(iocs):
    seen = {}
    for ioc in iocs:
        iid = ioc["id"]
        if iid not in seen or ioc["confidence"] > seen[iid]["confidence"]:
            seen[iid] = ioc
    return list(seen.values())


def main():
    p = argparse.ArgumentParser(description="SOC TI Feed Ingestion")
    p.add_argument("--source", default="all")
    p.add_argument("--output", default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--min-confidence", type=int, default=DEFAULT_MIN_CONFIDENCE)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    sources = list(FEEDS.keys()) if args.source == "all" else [args.source]
    if args.source != "all" and args.source not in FEEDS:
        log.error("unknown_source", source=args.source); sys.exit(1)

    all_iocs = []
    for src in sources:
        handler = HANDLERS.get(src)
        if not handler:
            log.warning("no_handler", source=src); continue
        iocs = [i for i in handler(FEEDS[src]) if i["confidence"] >= args.min_confidence]
        all_iocs.extend(iocs)

    deduped = deduplicate(all_iocs)
    log.info("complete", total=len(deduped))

    if not args.dry_run:
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_file = out / f"{args.source}_{ts}.json"
        out_file.write_text(json.dumps(deduped, indent=2))
        log.info("written", path=str(out_file))
    else:
        print(json.dumps(deduped[:3], indent=2))


if __name__ == "__main__":
    main()
