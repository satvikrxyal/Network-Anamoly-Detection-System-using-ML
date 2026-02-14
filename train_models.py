import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# Load NSL-KDD training dataset
train_data = pd.read_csv("Train_data.csv")

categorical_cols = ['protocol_type', 'service', 'flag']
numerical_cols = [col for col in train_data.columns if col not in categorical_cols + ['class']]

# Encoder
encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
encoded = encoder.fit_transform(train_data[categorical_cols])
encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out(categorical_cols))

# Scaler
scaler = StandardScaler()
scaled = scaler.fit_transform(train_data[numerical_cols])
scaled_df = pd.DataFrame(scaled, columns=numerical_cols)

# Final Training Matrix
X_train = pd.concat([scaled_df, encoded_df], axis=1)
y_train = train_data['class']

# Train Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save everything
joblib.dump(model, "models/nsl_model.pkl")
joblib.dump(encoder, "models/encoder_nsl.pkl")
joblib.dump(scaler, "models/scaler_nsl.pkl")

print("NSL-KDD model trained and saved successfully.")
