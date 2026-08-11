import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from features import extract_features

print("Loading dataset...")
df = pd.read_csv("../dataset/phishing.csv")
print(f"Loaded {len(df)} rows")

print("Extracting features (may take 1-3 minutes for 900k+ rows)...")
features = df["url"].astype(str).apply(extract_features).apply(pd.Series)
X, y = features, df["label"]
print("Feature extraction done.")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print("Training model...")
model = RandomForestClassifier(
    n_estimators=100, max_depth=10, class_weight="balanced",
    random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

print("\nEvaluating...")
preds = model.predict(X_test)
probs = model.predict_proba(X_test)[:, 1]
print(classification_report(y_test, preds))
print("ROC-AUC:", roc_auc_score(y_test, probs))

joblib.dump(model, "model.pkl")
joblib.dump(list(X.columns), "feature_names.pkl")
print("\nSaved model.pkl and feature_names.pkl")