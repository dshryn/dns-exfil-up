import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
    matthews_corrcoef,
    cohen_kappa_score,
    log_loss,
    brier_score_loss,
    balanced_accuracy_score,
    RocCurveDisplay,
    PrecisionRecallDisplay
)
from sklearn.model_selection import train_test_split
import joblib
from pathlib import Path

BASE = Path(__file__).resolve().parent
PROJECT_ROOT = BASE.parent

DATA_FILE = BASE / "models/dns_dataset.csv"
MODEL_PATH = BASE / "models" / "dns_rf_model.pkl"

OUTPUT_DIR = PROJECT_ROOT / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


def main():
    df = pd.read_csv(DATA_FILE)

    FEATURES = [
        "length",
        "num_digits",
        "num_subdomains",
        "entropy",
        "vowel_ratio",
        "unique_ratio",
        "longest_label",
        "consonant_ratio",
        "digit_ratio",
        "special_ratio",
        "repeated_char_ratio"
    ]

    X = df[FEATURES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=15,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train_scaled, y_train)
    model.feature_names_in_ = FEATURES

    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    THRESHOLD = 0.65
    y_pred = (y_prob >= THRESHOLD).astype(int)

    print("\nMODEL PERFORMANCE\n")

    report = classification_report(y_test, y_pred, digits=3)
    print(report)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print("\nConfusion Matrix:")
    print(cm)

    print("\nAdvanced Metrics:")
    print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")
    print(f"PR-AUC: {average_precision_score(y_test, y_prob):.4f}")
    print(f"MCC: {matthews_corrcoef(y_test, y_pred):.4f}")
    print(f"Cohen Kappa: {cohen_kappa_score(y_test, y_pred):.4f}")
    print(f"Log Loss: {log_loss(y_test, y_prob):.4f}")
    print(f"Brier Score: {brier_score_loss(y_test, y_prob):.4f}")
    print(f"Balanced Accuracy: {balanced_accuracy_score(y_test, y_pred):.4f}")

    specificity = tn / (tn + fp)
    print(f"Specificity: {specificity:.4f}")


    # confusion matrix

    plt.figure()
    sns.heatmap(cm, annot=True, fmt='d')
    plt.title("Confusion Matrix - DNS Exfiltration Detection")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.savefig(OUTPUT_DIR / "confusion_matrix.png")
    plt.close()


    # feature importance

    importances = model.feature_importances_
    feat_df = pd.Series(importances, index=FEATURES).sort_values()

    plt.figure()
    feat_df.plot(kind="barh")
    plt.title("Feature Importance (Random Forest)")
    plt.xlabel("Importance Score")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "feature_importance.png")
    plt.close()

    # save
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "features": FEATURES
        },
        MODEL_PATH
    )

    print("\nMODEL and GRAPHS SAVED IN /outputs\n")


if __name__ == "__main__":
    main()