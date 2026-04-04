import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    matthews_corrcoef,
    cohen_kappa_score,
    log_loss,
    brier_score_loss,
    balanced_accuracy_score
)
from sklearn.model_selection import train_test_split
import joblib
from pathlib import Path

BASE = Path(__file__).resolve().parent
PROJECT_ROOT = BASE.parent

DATA_FILE = BASE / "models/dns_dataset.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "dns_rf_model.pkl"


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

    # store feature names inside model
    model.feature_names_in_ = FEATURES

    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    THRESHOLD = 0.65
    y_pred = (y_prob >= THRESHOLD).astype(int)

    print("\nClassification Report:\n")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:\n")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)

    tn, fp, fn, tp = cm.ravel()

    print("\nAdvanced Metrics:\n")
    print("ROC-AUC:", roc_auc_score(y_test, y_prob))
    print("PR-AUC:", average_precision_score(y_test, y_prob))
    print("MCC:", matthews_corrcoef(y_test, y_pred))
    print("Cohen Kappa:", cohen_kappa_score(y_test, y_pred))
    print("Log Loss:", log_loss(y_test, y_prob))
    print("Brier Score:", brier_score_loss(y_test, y_prob))
    print("Balanced Accuracy:", balanced_accuracy_score(y_test, y_pred))

    specificity = tn / (tn + fp) if (tn + fp) else 0
    print("Specificity:", specificity)

    # save together
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "features": FEATURES
        },
        MODEL_PATH
    )

    print("\nMODEL SAVED")


if __name__ == "__main__":
    main()