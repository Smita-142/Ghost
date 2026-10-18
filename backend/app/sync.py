"""Idempotently synchronize recent NVD records and OSV package evidence."""
import argparse
import json

from app.services.vulnerability_sync import synchronize_vulnerabilities


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=30, help="Publication window in days (1-120)")
    parser.add_argument("--cve-id", help="Import one CVE ID instead of a publication window")
    parser.add_argument("--no-osv", action="store_true", help="Skip OSV package mapping lookups")
    args = parser.parse_args()
    if not 1 <= args.days <= 120:
        parser.error("--days must be between 1 and 120")
    print(json.dumps(synchronize_vulnerabilities(days=args.days, cve_id=args.cve_id, include_osv=not args.no_osv), indent=2))


if __name__ == "__main__":
    main()
