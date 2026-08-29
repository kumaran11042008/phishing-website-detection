import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load dataset
data = pd.read_csv("dataset/phishing.csv")

# Remove index column
if "index" in data.columns:
    data = data.drop(columns=["index"])

# Features and Target
X = data.drop("Result", axis=1)
y = data["Result"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Create model
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

# Train model
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("=" * 60)
print(f"Accuracy : {accuracy*100:.2f}%")

print("\nClassification Report")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, "model/phishing_model.pkl")

print("\nModel Saved Successfully!")