"""Fetch reproducible, small NVD CVE snapshots without third-party packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from tara_maintenance.baseline import JsonObject

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_NOTICE = (
    "This product uses data from the NVD API but is not endorsed or certified by the NVD."
)
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def fetch_snapshot(
    cve_ids: list[str], destination: Path, delay_seconds: float = 6.0
) -> JsonObject:
    """Fetch selected CVEs sequentially and write raw responses plus provenance."""

    destination.mkdir(parents=True, exist_ok=True)
    records = []
    for index, cve_id in enumerate(cve_ids):
        normalized = cve_id.upper()
        if not CVE_ID.fullmatch(normalized):
            raise ValueError(f"Invalid CVE identifier: {cve_id}")
        if index and delay_seconds:
            time.sleep(delay_seconds)
        url = NVD_API + normalized
        headers = {"Accept": "application/json", "User-Agent": "tara-maintenance-research"}
        if os.environ.get("NVD_API_KEY"):
            headers["apiKey"] = os.environ["NVD_API_KEY"]
        request = Request(url, headers=headers)
        with urlopen(request, timeout=60) as response:
            payload = response.read()
        document = json.loads(payload)
        if document.get("totalResults") != 1:
            raise ValueError(f"NVD returned {document.get('totalResults')} records for {normalized}")
        filename = f"{normalized}.json"
        (destination / filename).write_bytes(payload)
        records.append(
            {
                "cve_id": normalized,
                "file": filename,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "source_url": url,
                "api_timestamp": document.get("timestamp"),
                "last_modified": document["vulnerabilities"][0]["cve"].get("lastModified"),
            }
        )

    manifest = {
        "dataset_id": "nvd-bbw-selected-v1",
        "source": "National Vulnerability Database (NVD) CVE API 2.0",
        "license": "NIST publications are in the public domain under Title 17 U.S.C.",
        "notice": NVD_NOTICE,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "request_delay_seconds": delay_seconds,
        "records": records,
    }
    (destination / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cve_ids", nargs="+", help="CVE identifiers to retrieve")
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--delay", type=float, default=6.0, help="Delay between requests")
    args = parser.parse_args(argv)
    if args.delay < 0:
        parser.error("--delay cannot be negative")
    manifest = fetch_snapshot(args.cve_ids, args.output_directory, args.delay)
    print(json.dumps({"records": len(manifest["records"]), "directory": str(args.output_directory)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
