import pandas as pd

# Source 1: malicious_phish.csv (multi-class -> binary)
mal = pd.read_csv("raw/malicious_phish.csv")
mal["label"] = mal["type"].apply(lambda t: 0 if t == "benign" else 1)
mal = mal[["url", "label"]]
print("Source 1 (malicious_phish.csv):", len(mal), "rows")

# Source 2: dataset_phishing.csv
web = pd.read_csv("raw/dataset_phishing.csv")
web["label"] = web["status"].apply(lambda s: 0 if s == "legitimate" else 1)
web = web[["url", "label"]]
print("Source 2 (dataset_phishing.csv):", len(web), "rows")

# Source 3: Tranco top domains (all safe)
safe = pd.read_csv("raw/tranco_top_1m.csv", names=["rank", "domain"])
safe["url"] = "https://" + safe["domain"]
safe = safe[["url"]].head(50000)
safe["label"] = 0
print("Source 3 (tranco top 50k):", len(safe), "rows")

# Source 4: Curated diverse safe domains - weighted x20 so they carry real influence
curated = pd.read_csv("raw/curated_safe.csv")
curated["label"] = 0
curated = pd.concat([curated] * 40, ignore_index=True)
print("Source 4 (curated safe, x20 weighted):", len(curated), "rows")

# Source 5: PhiUSIIL - label=1 means LEGITIMATE in this dataset, so we flip it
# to match our convention (0 = safe, 1 = threat)
phi = pd.read_csv("raw/PhiUSIIL_Phishing_URL_Dataset.csv")
phi = phi.rename(columns={"URL": "url"})
phi["label"] = phi["label"].apply(lambda l: 0 if l == 1 else 1)
phi = phi[["url", "label"]]
print("Source 5 (PhiUSIIL):", len(phi), "rows")

df = pd.concat([mal, web, safe, curated, phi]).drop_duplicates(subset="url").sample(frac=1, random_state=42).reset_index(drop=True)

df.to_csv("phishing.csv", index=False)
print("\nFinal combined dataset:")
print(df["label"].value_counts())
print(f"\nTotal rows: {len(df)}")