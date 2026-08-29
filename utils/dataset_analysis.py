import pandas as pd
import matplotlib.pyplot as plt

# Load the dataset
data = pd.read_csv("dataset/phishing.csv")

# Display first 5 rows
print("\nFirst 5 Rows:")
print(data.head())

# Display dataset information
print("\nDataset Information:")
print(data.info())

# Display shape
print("\nRows and Columns:")
print(data.shape)

# Display column names
print("\nColumns:")
print(data.columns)

# Check missing values
print("\nMissing Values:")
print(data.isnull().sum())

# Check duplicate rows
print("\nDuplicate Rows:")
print(data.duplicated().sum())

# Statistical summary
print("\nStatistical Summary:")
print(data.describe())

# ==========================
# Label Distribution Graph
# ==========================

data.iloc[:, -1].value_counts().plot(kind="bar")

plt.title("Safe vs Phishing Websites")
plt.xlabel("Class")
plt.ylabel("Count")

plt.show()