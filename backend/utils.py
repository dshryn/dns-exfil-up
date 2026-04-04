from __future__ import annotations

import json
import math
from pathlib import Path


def parse_dns_log(path):
    records = []
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"DNS log not found: {path}")

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                try:
                    records.append(json.loads(line))
                except:
                    pass
    return records


def clean_query(q):
    if q is None:
        return ""

    s = str(q)

    # CLEANED VERSION (fix garbage display)
    return "".join(c if c.isalnum() or c in ".-" else "." for c in s)


def entropy(s):
    if not s:
        return 0.0

    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1

    ent = 0.0
    for count in freq.values():
        p = count / len(s)
        ent -= p * math.log2(p)

    return ent


def vowel_ratio(s):
    if not s:
        return 0.0
    return sum(1 for c in s.lower() if c in "aeiou") / len(s)


def unique_ratio(s):
    if not s:
        return 0.0
    return len(set(s)) / len(s)


def extract_features(record):
    q = clean_query(record.get("query", "")).strip().rstrip(".")

    qtype = record.get("qtype_name") or f"QTYPE_{record.get('qtype', 0)}"

    return {
        "query": q,
        "length": len(q),
        "num_digits": sum(c.isdigit() for c in q),
        "num_subdomains": q.count("."),
        "entropy": entropy(q.replace(".", "")),
        "vowel_ratio": vowel_ratio(q.replace(".", "")),
        "unique_ratio": unique_ratio(q.replace(".", "")),
        "src_ip": record.get("id.orig_h", "-"),
        "timestamp": record.get("ts"),
        "qtype": qtype,
    }