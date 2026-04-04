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


def extract_features(record):
    q = clean_query(record.get("query", "")).strip().rstrip(".")
    raw = q.replace(".", "")

    length = len(q)
    num_digits = sum(c.isdigit() for c in q)
    num_subdomains = max(q.count("."), 0)

    ent = entropy(raw)

    vowels = "aeiou"
    vowel_ratio = sum(c in vowels for c in raw.lower()) / length if length else 0
    unique_ratio = len(set(raw)) / length if length else 0

    # new features
    parts = q.split(".") if q else []
    longest_label = max((len(p) for p in parts), default=0)

    consonant_ratio = sum(
        c.isalpha() and c not in vowels for c in raw.lower()
    ) / length if length else 0

    digit_ratio = num_digits / length if length else 0

    special_ratio = sum(not c.isalnum() for c in q) / length if length else 0

    repeated_char_ratio = 1 - (len(set(raw)) / length) if length else 0

    qtype = record.get("qtype_name") or f"QTYPE_{record.get('qtype', 0)}"

    return {
        "query": q,
        "length": length,
        "num_digits": num_digits,
        "num_subdomains": num_subdomains,
        "entropy": ent,
        "vowel_ratio": vowel_ratio,
        "unique_ratio": unique_ratio,
        "longest_label": longest_label,
        "consonant_ratio": consonant_ratio,
        "digit_ratio": digit_ratio,
        "special_ratio": special_ratio,
        "repeated_char_ratio": repeated_char_ratio,
        "src_ip": record.get("id.orig_h", "-"),
        "timestamp": record.get("ts"),
        "qtype": qtype,
    }