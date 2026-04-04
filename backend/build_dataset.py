import json
import pandas as pd
import numpy as np
from pathlib import Path
import math

BASE = Path(__file__).resolve().parent

ATTACK_DIR = BASE.parent / "zeek_logs" / "attacks"
BENIGN_DIR = BASE.parent / "zeek_logs" / "benign"

OUTPUT_FILE = BASE / "models/dns_dataset.csv"


def shannon_entropy(s):
    if not s:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features_from_query(query):
    if not query:
        return None

    parts = query.split(".")
    length = len(query)

    num_digits = sum(c.isdigit() for c in query)
    num_subdomains = max(len(parts) - 2, 0)

    entropy = shannon_entropy(query)

    vowels = "aeiou"
    vowel_ratio = sum(c in vowels for c in query.lower()) / length
    unique_ratio = len(set(query)) / length

    longest_label = max(len(p) for p in parts)

    consonant_ratio = sum(
        c.isalpha() and c not in vowels for c in query.lower()
    ) / length

    digit_ratio = num_digits / length

    special_ratio = sum(not c.isalnum() for c in query) / length

    repeated_char_ratio = 1 - (len(set(query)) / length)

    return {
        "length": length,
        "num_digits": num_digits,
        "num_subdomains": num_subdomains,
        "entropy": entropy,
        "vowel_ratio": vowel_ratio,
        "unique_ratio": unique_ratio,
        "longest_label": longest_label,
        "consonant_ratio": consonant_ratio,
        "digit_ratio": digit_ratio,
        "special_ratio": special_ratio,
        "repeated_char_ratio": repeated_char_ratio
    }


def process_folder(folder_path, label):
    rows = []

    for subdir in folder_path.iterdir():
        dns_file = subdir / "dns.log"

        if not dns_file.exists():
            continue

        with open(dns_file, "r") as f:
            for line in f:
                try:
                    record = json.loads(line)
                    query = record.get("query", "")

                    feats = extract_features_from_query(query)
                    if not feats:
                        continue

                    feats["label"] = label
                    rows.append(feats)

                except:
                    continue

    return rows


def main():
    print("ATTACK DIR:", ATTACK_DIR)
    print("BENIGN DIR:", BENIGN_DIR)

    print("Processing ATTACK logs...")
    attack_rows = process_folder(ATTACK_DIR, 1)

    print("Processing BENIGN logs...")
    benign_rows = process_folder(BENIGN_DIR, 0)

    data = attack_rows + benign_rows

    df = pd.DataFrame(data)

    df = df.dropna()
    df = df.sample(frac=1).reset_index(drop=True)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nDataset created: {OUTPUT_FILE}")
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()