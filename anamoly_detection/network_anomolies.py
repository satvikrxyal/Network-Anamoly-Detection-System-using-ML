import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder

import os

# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Load train data
train_data_path = os.path.join(script_dir, "Train_data.csv")
train_data = pd.read_csv(train_data_path)

# Identify categorical columns (excluding 'class')
categorical_cols = train_data.select_dtypes(include=['object']).columns.tolist()
categorical_cols.remove('class')

# Perform One-Hot Encoding for train data
encoder = OneHotEncoder(handle_unknown='ignore')
encoded_train = pd.DataFrame(encoder.fit_transform(train_data[categorical_cols]).toarray())

# Reassign column names
encoded_train.columns = encoder.get_feature_names_out(categorical_cols)

# Concatenate encoded columns with original data
train_data_encoded = pd.concat([train_data.drop(columns=categorical_cols), encoded_train], axis=1)

# Separate features and labels for train data
X_train = train_data_encoded.drop('class', axis=1)
y_train = train_data_encoded['class']

# Initialize and train the Isolation Forest model
isolation_forest = IsolationForest(contamination=0.1)
isolation_forest.fit(X_train)

# Load test data
test_data_path = os.path.join(script_dir, "Test_data.csv")
test_data = pd.read_csv(test_data_path)

# Check if 'class' column exists in test data
if 'class' in test_data.columns:
    # Drop 'class' column from test data
    test_data.drop(columns=['class'], inplace=True)

# Perform One-Hot Encoding for test data
encoded_test = pd.DataFrame(encoder.transform(test_data[categorical_cols]).toarray())
encoded_test.columns = encoder.get_feature_names_out(categorical_cols)
test_data_encoded = pd.concat([test_data.drop(columns=categorical_cols), encoded_test], axis=1)

# Detect anomalies in the test data
anomaly_predictions = isolation_forest.predict(test_data_encoded)

# Print the predictions
print("Anomaly Predictions for Test Data:")
print(anomaly_predictions)

# Save the predictions to a CSV file
test_data['anomaly_prediction'] = anomaly_predictions
output_path = os.path.join(script_dir, "test_data_with_anomaly_predictions.csv")
test_data.to_csv(output_path, index=False)
print("Anomaly predictions saved to 'test_data_with_anomaly_predictions.csv'")
