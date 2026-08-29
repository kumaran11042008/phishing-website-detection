import joblib
import pandas as pd

from utils.feature_extractor import FeatureExtractor
from utils.risk_engine import RiskEngine


class Predictor:

    def __init__(self):
        self.model = joblib.load("model/phishing_model.pkl")

    def predict(self, url):

        # ==========================================
        # Extract 30 Features
        # ==========================================

        features = FeatureExtractor(url).extract_features()

        print("\nExtracted Features:")
        print(features)

        print("\nNumber of Features:")
        print(len(features))

        # ==========================================
        # Check Feature Count
        # ==========================================

        if len(features) != 30:
            raise ValueError(
                f"Expected 30 features, but got {len(features)}"
            )

        # ==========================================
        # Dataset Feature Order
        # ==========================================

        feature_names = [

            "having_IPhaving_IP_Address",
            "URLURL_Length",
            "Shortining_Service",
            "having_At_Symbol",
            "double_slash_redirecting",
            "Prefix_Suffix",
            "having_Sub_Domain",
            "SSLfinal_State",
            "Domain_registeration_length",
            "Favicon",
            "port",
            "HTTPS_token",
            "Request_URL",
            "URL_of_Anchor",
            "Links_in_tags",
            "SFH",
            "Submitting_to_email",
            "Abnormal_URL",
            "Redirect",
            "on_mouseover",
            "RightClick",
            "popUpWidnow",
            "Iframe",
            "age_of_domain",
            "DNSRecord",
            "web_traffic",
            "Page_Rank",
            "Google_Index",
            "Links_pointing_to_page",
            "Statistical_report"

        ]

        # ==========================================
        # Create DataFrame
        # ==========================================

        input_data = pd.DataFrame(
            [features],
            columns=feature_names
        )

        # ==========================================
        # ML Prediction
        # ==========================================

        prediction = self.model.predict(input_data)[0]

        probability = self.model.predict_proba(input_data)[0]

        confidence = float(
            round(max(probability) * 100, 2)
        )

        # ==========================================
        # Convert ML Prediction
        # ==========================================

        if prediction == 1:

            result = "Phishing Website"

        else:

            result = "Legitimate Website"

        # ==========================================
        # HYBRID RISK ENGINE
        # ==========================================

        risk_engine = RiskEngine(
            url,
            result,
            confidence
        )

        risk_result = risk_engine.calculate()

        # ==========================================
        # FINAL RESULT
        # ==========================================

        return {

            "prediction": result,

            "confidence": confidence,

            "risk": risk_result["risk"],

            "risk_score": risk_result["score"],

            "reasons": risk_result["reasons"]

        }


# ==========================================
# TESTING
# ==========================================

if __name__ == "__main__":

    url = input("Enter URL: ")

    predictor = Predictor()

    result = predictor.predict(url)

    print("\n================================")
    print("Prediction Result")
    print("================================")

    print("Prediction :", result["prediction"])

    print("Confidence :", result["confidence"], "%")

    print("Risk       :", result["risk"])

    print("Risk Score :", result["risk_score"], "/ 100")

    print("\nWhy is this risky?")

    if result["reasons"]:

        for reason in result["reasons"]:
            print("-", reason)

    else:

        print("- No major suspicious indicators detected.")