from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DEFAULT_LOG = PROJECT_ROOT / "zeek-logs" / "dns.log"

DEFAULT_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200/dns-logs/_doc")
DEFAULT_USERNAME = os.getenv("OPENSEARCH_USERNAME")
DEFAULT_PASSWORD = os.getenv("OPENSEARCH_PASSWORD")


def ingest_dns_log(
    log_path: Path,
    opensearch_url: str,
    username: str | None = None,
    password: str | None = None,
) -> None:
    if not log_path.exists():
        raise FileNotFoundError(f"DNS log not found: {log_path}")

    auth = (username, password) if username and password else None
    inserted = 0
    skipped = 0
    failed = 0

    with requests.Session() as session:
        with log_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()

                if not line or line.startswith("#"):
                    skipped += 1
                    continue

                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    failed += 1
                    print(f"Skipping invalid JSON on line {line_no}")
                    continue

                try:
                    response = session.post(
                        opensearch_url,
                        json=doc,
                        auth=auth,
                        timeout=15,
                    )
                    response.raise_for_status()
                    inserted += 1
                except requests.RequestException as exc:
                    failed += 1
                    print(f"Failed to ingest line {line_no}: {exc}")

    print("\nIngestion complete.")
    print(f"Inserted: {inserted}")
    print(f"Skipped:  {skipped}")
    print(f"Failed:   {failed}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest Zeek dns.log records into OpenSearch")
    parser.add_argument(
        "--log",
        type=Path,
        default=DEFAULT_LOG,
        help="Path to Zeek dns.log",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=DEFAULT_URL,
        help="OpenSearch document endpoint URL",
    )
    parser.add_argument(
        "--username",
        type=str,
        default=DEFAULT_USERNAME,
        help="OpenSearch username",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=DEFAULT_PASSWORD,
        help="OpenSearch password",
    )

    args = parser.parse_args()
    ingest_dns_log(args.log, args.url, args.username, args.password)


if __name__ == "__main__":
    main()