import pandas as pd
import joblib
import numpy as np

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    auc
)
import matplotlib.pyplot as plt

# Load
df = pd.read_csv("../models/dns_features.csv")

features = [
    "length",
    "num_digits",
    "num_subdomains",
    "entropy",
    "vowel_ratio",
    "unique_ratio"
]

# Label (same logic as training)
df["label"] = (
    (df["entropy"] > 3.5) &
    (df["length"] > 50) &
    (df["num_subdomains"] > 2)
).astype(int)

X = df[features]
y = df["label"]

# Load model
model = joblib.load("../models/dns_rf_model.pkl")
scaler = joblib.load("../models/scaler.pkl")

X_scaled = scaler.transform(X)

# Predictions
y_pred = model.predict(X_scaled)
y_prob = model.predict_proba(X_scaled)[:, 1]

# Metrics
print("Accuracy:", accuracy_score(y, y_pred))
print("Precision:", precision_score(y, y_pred))
print("Recall:", recall_score(y, y_pred))
print("F1 Score:", f1_score(y, y_pred))

# Confusion Matrix
cm = confusion_matrix(y, y_pred)
print("Confusion Matrix:\n", cm)

# ROC Curve
fpr, tpr, _ = roc_curve(y, y_prob)
roc_auc = auc(fpr, tpr)

plt.figure()
plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve")
plt.legend()
plt.savefig("roc_curve.png")

# Confusion Matrix Plot
plt.figure()
plt.imshow(cm)
plt.title("Confusion Matrix")
plt.colorbar()
plt.savefig("confusion_matrix.png")