import pandas as pd
from sklearn.model_selection import train_test_split

# Load dataset
data = pd.read_csv("dataset/phishing.csv")

print("=" * 50)
print("Original Shape:", data.shape)

# Remove index column
if "index" in data.columns:
    data = data.drop(columns=["index"])

# Remove duplicate rows
data = data.drop_duplicates()

print("After Cleaning:", data.shape)

# Check missing values
print("\nMissing Values")
print(data.isnull().sum())

# Features
X = data.drop("Result", axis=1)

# Target
y = data["Result"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining Features:", X_train.shape)
print("Testing Features:", X_test.shape)

print("\nPreprocessing Completed Successfully.")