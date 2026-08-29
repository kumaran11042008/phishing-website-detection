from utils.webpage_features import WebpageFeatures

url = input("Enter URL: ")

obj = WebpageFeatures(url)

print()

print(obj.extract_features())