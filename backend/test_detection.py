from pathlib import Path
import time

from utils import parse_dns_log
from detection import analyze_records

print("Starting detection...")

BASE = Path(__file__).resolve().parent
log_path = BASE.parent / "zeek-logs" / "dns.log"

print("Using log:", log_path)

records = parse_dns_log(log_path)
print("Records loaded:", len(records))

start = time.time()
results = analyze_records(records)
end = time.time()

print("\nDNS DETECTION RESULTS\n")

if not results:
    print("⚠️ No suspicious records found")

else:
    print(f"{'Score':<8}{'Severity':<12}{'IP':<18}{'Type':<10}{'Query'}")
    print("="*100)

    for r in results[:25]:
        print(f"{r['score']:<8}{r['severity']:<12}{r['src_ip']:<18}{r['qtype']:<10}{r['query']}")

print("\nSUMMARY")
print(f"Total records: {len(records)}")
print(f"Suspicious: {len(results)}")
print(f"Analysis time: {round(end-start,3)} sec")