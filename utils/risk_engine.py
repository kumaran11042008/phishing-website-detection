from urllib.parse import urlparse
import re


class RiskEngine:

    def __init__(self, url, ml_prediction, ml_confidence):

        self.url = url.strip()
        self.ml_prediction = ml_prediction
        self.ml_confidence = ml_confidence

        self.score = 0
        self.reasons = []

    # ==========================================
    # 1. IP ADDRESS
    # ==========================================

    def check_ip_address(self):

        domain = urlparse(self.url).netloc

        pattern = r"(\d{1,3}\.){3}\d{1,3}"

        if re.search(pattern, domain):

            self.score += 30

            self.reasons.append(
                "Website uses an IP address instead of a normal domain."
            )

    # ==========================================
    # 2. HTTP
    # ==========================================

    def check_https(self):

        if self.url.lower().startswith("http://"):

            self.score += 15

            self.reasons.append(
                "Website is not using HTTPS."
            )

    # ==========================================
    # 3. @ SYMBOL
    # ==========================================

    def check_at_symbol(self):

        if "@" in self.url:

            self.score += 20

            self.reasons.append(
                "URL contains an @ symbol."
            )

    # ==========================================
    # 4. VERY LONG URL
    # ==========================================

    def check_url_length(self):

        if len(self.url) > 100:

            self.score += 15

            self.reasons.append(
                "URL is unusually long."
            )

    # ==========================================
    # 5. SUSPICIOUS KEYWORDS
    # ==========================================

    def check_keywords(self):

        keywords = [

            "login",
            "signin",
            "verify",
            "verification",
            "account",
            "update",
            "secure",
            "password",
            "bank",
            "wallet",
            "payment",
            "confirm"

        ]

        url_lower = self.url.lower()

        found = []

        for keyword in keywords:

            if keyword in url_lower:

                found.append(keyword)

        if found:

            self.score += min(len(found) * 5, 20)

            self.reasons.append(
                "Suspicious security-related keyword(s): "
                + ", ".join(found)
            )

    # ==========================================
    # 6. URL SHORTENER
    # ==========================================

    def check_shortener(self):

        shorteners = [

            "bit.ly",
            "tinyurl.com",
            "t.co",
            "ow.ly",
            "is.gd",
            "cutt.ly",
            "shorturl.at"

        ]

        domain = urlparse(self.url).netloc.lower()

        for service in shorteners:

            if service in domain:

                self.score += 20

                self.reasons.append(
                    "URL uses a URL shortening service."
                )

                break

    # ==========================================
    # 7. MULTIPLE SUBDOMAINS
    # ==========================================

    def check_subdomains(self):

        domain = urlparse(self.url).netloc

        dots = domain.count(".")

        if dots >= 4:

            self.score += 15

            self.reasons.append(
                "URL contains an unusually large number of subdomains."
            )

    # ==========================================
    # FINAL RISK CALCULATION
    # ==========================================

    def calculate(self):

        # Run all security checks

        self.check_ip_address()
        self.check_https()
        self.check_at_symbol()
        self.check_url_length()
        self.check_keywords()
        self.check_shortener()
        self.check_subdomains()

        # ======================================
        # Combine ML + Rule Engine
        # ======================================

        final_score = self.score

        # ML prediction

        if self.ml_prediction == "Phishing Website":

            final_score += 40

        # ML confidence adjustment

        if self.ml_prediction == "Phishing Website":

            if self.ml_confidence >= 80:
                final_score += 20

            elif self.ml_confidence >= 60:
                final_score += 10

        # ======================================
        # Limit score
        # ======================================

        final_score = min(final_score, 100)

        # ======================================
        # Determine final risk
        # ======================================

        if final_score >= 60:

            risk = "High"

        elif final_score >= 30:

            risk = "Medium"

        else:

            risk = "Low"

        # ======================================
        # If ML strongly says phishing
        # ======================================

        if (
            self.ml_prediction == "Phishing Website"
            and self.ml_confidence >= 80
        ):

            risk = "High"

        return {

            "risk": risk,

            "score": final_score,

            "reasons": self.reasons

        }
if __name__ == "__main__":

    url = input("Enter URL: ")

    engine = RiskEngine(
        url,
        "Phishing Website",
        75
    )

    result = engine.calculate()

    print("\n==============================")
    print("Risk Engine Result")
    print("==============================")

    print("Risk :", result["risk"])
    print("Score:", result["score"])

    print("\nReasons:")

    for reason in result["reasons"]:

        print("-", reason)