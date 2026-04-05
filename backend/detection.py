from __future__ import annotations

from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from utils import extract_features

BASE_DIR = Path(__file__).resolve().parent

bundle = joblib.load(BASE_DIR / "models/dns_rf_model.pkl")

model = bundle["model"]
scaler = bundle["scaler"]
FEATURES = bundle["features"]

print("MODEL LOADED WITH FEATURES:", FEATURES)

ALERT_THRESHOLD = 40


def severity(score):
    if score > 85:
        return "CRITICAL"
    elif score > 70:
        return "HIGH"
    elif score > 50:
        return "MEDIUM"
    return "LOW"


def analyze_records(records):
    rows = []
    meta = []

    for r in records:
        f = extract_features(r)
        rows.append([f.get(k, 0) for k in FEATURES])
        meta.append(f)

    if not rows:
        return []

    df = pd.DataFrame(rows, columns=FEATURES)
    df = df.apply(pd.to_numeric, errors="coerce").fillna(0.0)

    if list(df.columns) != list(FEATURES):
        raise ValueError("Feature mismatch between model and input")

    X = scaler.transform(df)
    probs = model.predict_proba(X)[:, 1]

    results = []

    for i, prob in enumerate(probs):
        f = meta[i]

        prob = np.clip(prob, 0.01, 0.99)
        prob = prob ** 0.7

        entropy_score = min(f["entropy"] / 5, 1) * 20
        subdomain_score = min(f["num_subdomains"] / 10, 1) * 20
        ml_score = prob * 60

        score = round(ml_score + entropy_score + subdomain_score, 2)

        if score < ALERT_THRESHOLD:
            continue

        results.append({
            "timestamp": f["timestamp"],
            "src_ip": f["src_ip"],
            "query": f["query"][:80],
            "qtype": f["qtype"],
            "score": score,
            "severity": severity(score),
            "entropy": round(f["entropy"], 3),
            "num_subdomains": f["num_subdomains"],
            "length": f["length"],
            "reasons": [
                f"Entropy: {round(f['entropy'], 2)}",
                f"Subdomains: {f['num_subdomains']}",
                f"ML confidence: {round(prob, 3)}"
            ]
        })

    return sorted(results, key=lambda x: -x["score"])