from __future__ import annotations

import json
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
MODELS_DIR = PROJECT_ROOT / "models"

DATA_PATH = MODELS_DIR / "dns_features.csv"
MODEL_PATH = MODELS_DIR / "dns_rf_model.pkl"
SCALER_PATH = MODELS_DIR / "scaler.pkl"
METRICS_PATH = MODELS_DIR / "training_metrics.json"
IMPORTANCE_PATH = MODELS_DIR / "feature_importance.csv"
IMPORTANCE_PLOT_PATH = MODELS_DIR / "feature_importance.png"
CM_PLOT_PATH = MODELS_DIR / "confusion_matrix.png"
ROC_PLOT_PATH = MODELS_DIR / "roc_curve.png"

FEATURES = [
    "length",
    "num_digits",
    "num_subdomains",
    "entropy",
    "vowel_ratio",
    "unique_ratio",
]




def build_labels(df: pd.DataFrame) -> pd.Series:
    """
    Build labels using the heuristic used by the project.
    If a label column already exists, keep it.
    """
    if "label" in df.columns:
        labels = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)
        return labels

    return (
        (df["entropy"] > 3.5)
        & (df["length"] > 50)
        & (df["num_subdomains"] > 2)
    ).astype(int)


def save_feature_importance(model: RandomForestClassifier) -> None:
    importance_df = (
        pd.DataFrame(
            {
                "feature": FEATURES,
                "importance": model.feature_importances_,
            }
        )
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )

    importance_df.to_csv(IMPORTANCE_PATH, index=False)

    plt.figure(figsize=(8, 4.8))
    plt.barh(importance_df["feature"][::-1], importance_df["importance"][::-1])
    plt.title("Feature Importance")
    plt.xlabel("Importance")
    plt.tight_layout()
    plt.savefig(IMPORTANCE_PLOT_PATH, dpi=200)
    plt.close()


def save_confusion_matrix(y_test, y_pred) -> None:
    cm = confusion_matrix(y_test, y_pred)

    plt.figure(figsize=(5.5, 4.5))
    plt.imshow(cm)
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted Label")
    plt.ylabel("True Label")
    plt.colorbar()
    plt.xticks([0, 1], ["Benign", "Malicious"])
    plt.yticks([0, 1], ["Benign", "Malicious"])

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, str(cm[i, j]), ha="center", va="center")

    plt.tight_layout()
    plt.savefig(CM_PLOT_PATH, dpi=200)
    plt.close()


def save_roc_curve(y_test, y_prob) -> float:
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(5.5, 4.5))
    plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.3f}")
    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.title("ROC Curve")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(ROC_PLOT_PATH, dpi=200)
    plt.close()

    return roc_auc


def main() -> None:
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Feature dataset not found: {DATA_PATH}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(DATA_PATH)

    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        raise RuntimeError(f"Missing required columns in dataset: {missing}")

    df = df.dropna(subset=FEATURES).copy()
    df[FEATURES] = df[FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    df["label"] = build_labels(df).astype(int)

    if df["label"].nunique() < 2:
        raise RuntimeError(
            "Training data must contain at least two classes. "
            "Your current labels contain only one class."
        )

    X = df[FEATURES]
    y = df["label"]

    test_size = 0.3 if len(df) >= 10 else 0.5
    stratify = y if y.value_counts().min() >= 2 else None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=42,
        stratify=stratify,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )

    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
    }

    try:
        metrics["roc_auc"] = float(save_roc_curve(y_test, y_prob))
    except ValueError:
        metrics["roc_auc"] = None

    save_confusion_matrix(y_test, y_pred)
    save_feature_importance(model)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    METRICS_PATH.write_text(json.dumps(metrics, indent=2))

    print("FINAL MODEL TRAINED")
    print(f"Accuracy:  {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall:    {metrics['recall']:.4f}")
    print(f"F1 Score:  {metrics['f1_score']:.4f}")
    if metrics["roc_auc"] is not None:
        print(f"ROC AUC:   {metrics['roc_auc']:.4f}")

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))

    print(f"\nSaved model to: {MODEL_PATH}")
    print(f"Saved scaler to: {SCALER_PATH}")
    print(f"Saved metrics to: {METRICS_PATH}")
    print(f"Saved feature importance table to: {IMPORTANCE_PATH}")
    print(f"Saved feature importance plot to: {IMPORTANCE_PLOT_PATH}")
    print(f"Saved confusion matrix plot to: {CM_PLOT_PATH}")
    print(f"Saved ROC curve plot to: {ROC_PLOT_PATH}")


if __name__ == "__main__":
    main()