import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler

print("Loading NSL dataset...")

df = pd.read_csv("datasets/nsl_train.csv")
df.columns = df.columns.str.strip()

target_column = "class"

categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
categorical_cols.remove(target_column)

encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
encoded = encoder.fit_transform(df[categorical_cols])
encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out())

df_processed = pd.concat(
    [df.drop(columns=categorical_cols).reset_index(drop=True),
     encoded_df.reset_index(drop=True)],
    axis=1
)

X = df_processed.drop(target_column, axis=1)
y = df_processed[target_column]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_scaled, y)

joblib.dump(model, "models/nsl_model.pkl")
joblib.dump(scaler, "models/nsl_scaler.pkl")
joblib.dump(list(X.columns), "models/nsl_features.pkl")
joblib.dump(encoder, "models/nsl_encoder.pkl")

print("NSL model saved successfully.")
