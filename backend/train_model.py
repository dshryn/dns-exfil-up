import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import joblib
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA_FILE = BASE / "models/dns_dataset.csv"


def main():
    df = pd.read_csv(DATA_FILE)

    features = [
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

    X = df[features]
    y = df["label"]

    # split
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

    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    THRESHOLD = 0.65

    y_pred = (y_prob >= THRESHOLD).astype(int)

    # print("\nTHRESHOLD USED:", THRESHOLD)

    print("\nClassification metrics:\n")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:\n")
    print(confusion_matrix(y_test, y_pred))

    # joblib
    joblib.dump(model, BASE / "models/dns_rf_model.pkl")
    joblib.dump(scaler, BASE / "models/scaler.pkl")

    print("\nMODEL SAVED")


if __name__ == "__main__":
    main()