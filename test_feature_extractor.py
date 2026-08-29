from utils.feature_extractor import FeatureExtractor

url = input("Enter URL: ")

extractor = FeatureExtractor(url)

features = extractor.extract_features()

print("\nExtracted Features")

print(features)