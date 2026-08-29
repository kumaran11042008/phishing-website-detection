import pandas as pd

df = pd.read_csv("dataset/phishing.csv")

print("Columns:")
print(df.columns.tolist())

print("\nNumber of Columns:", len(df.columns))

print("\nLast 5 Columns:")
print(df.columns[-5:])

print("\nFirst 5 Rows:")
print(df.head())