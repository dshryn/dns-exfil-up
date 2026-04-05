from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from backend.utils import extract_features as build_features
from backend.utils import parse_dns_log

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DEFAULT_INPUT = PROJECT_ROOT / "zeek-logs" / "dns.log"
DEFAULT_OUTPUT = PROJECT_ROOT / "models" / "dns_features.csv"


def build_feature_dataset(input_path: Path, output_path: Path) -> pd.DataFrame:
    records = parse_dns_log(input_path)

    if not records:
        raise RuntimeError(f"No DNS records found in {input_path}")

    rows = [build_features(r) for r in records]
    df = pd.DataFrame(rows)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"Feature extraction complete: {len(df)} records saved to {output_path}")
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract DNS features from Zeek dns.log")
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Path to Zeek dns.log",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output CSV path for extracted features",
    )

    args = parser.parse_args()
    build_feature_dataset(args.input, args.output)


if __name__ == "__main__":
    main()