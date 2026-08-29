import pandas as pd

data = pd.read_csv("dataset/phishing.csv")

print(data.columns.tolist())
print("\nDataset Shape:", data.shape)
print("\nFirst 5 Rows:")
print(data.head())