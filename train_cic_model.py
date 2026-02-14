import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

print("Loading CIC dataset...")

df = pd.read_csv("datasets/cic_combined.csv")
df.columns = df.columns.str.strip()

target_column = "Label"

df[target_column] = df[target_column].apply(
    lambda x: "normal" if x == "BENIGN" else "attack"
)

X = df.drop(target_column, axis=1)
y = df[target_column]

X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_scaled, y)

joblib.dump(model, "models/cic_model.pkl")
joblib.dump(scaler, "models/cic_scaler.pkl")
joblib.dump(list(X.columns), "models/cic_features.pkl")

print("CIC model saved successfully.")
