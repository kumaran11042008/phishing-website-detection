from utils.predictor import Predictor

predictor = Predictor()

url = input("Enter URL: ")

result = predictor.predict(url)

print()

print(result)