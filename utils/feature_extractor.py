import re
import socket
import requests
import whois
import tldextract

from urllib.parse import urlparse


class FeatureExtractor:

    def __init__(self, url):
        self.url = url.strip()

        if not self.url.startswith(("http://", "https://")):
            self.url = "http://" + self.url

        self.parsed = urlparse(self.url)
        self.domain = self.parsed.netloc.split(":")[0].lower()

    # =========================================================
    # 1. having_IPhaving_IP_Address
    # =========================================================
    def having_ip_address(self):
        pattern = r"(\d{1,3}\.){3}\d{1,3}"

        if re.search(pattern, self.domain):
            return 1

        return -1

    # =========================================================
    # 2. URLURL_Length
    # =========================================================
    def url_length(self):

        length = len(self.url)

        if length < 54:
            return -1

        elif length <= 75:
            return 0

        return 1

    # =========================================================
    # 3. Shortining_Service
    # =========================================================
    def shortening_service(self):

        services = [
            "bit.ly",
            "goo.gl",
            "tinyurl.com",
            "ow.ly",
            "t.co",
            "is.gd",
            "buff.ly",
            "adf.ly",
            "bit.do",
            "cutt.ly",
            "shorturl.at"
        ]

        if any(service in self.domain for service in services):
            return 1

        return -1

    # =========================================================
    # 4. having_At_Symbol
    # =========================================================
    def having_at_symbol(self):

        if "@" in self.url:
            return 1

        return -1

    # =========================================================
    # 5. double_slash_redirecting
    # =========================================================
    def double_slash_redirecting(self):

        position = self.url.find("//", 8)

        if position != -1:
            return 1

        return -1

    # =========================================================
    # 6. Prefix_Suffix
    # =========================================================
    def prefix_suffix(self):

        domain = tldextract.extract(self.url).domain

        if "-" in domain:
            return 1

        return -1

    # =========================================================
    # 7. having_Sub_Domain
    # =========================================================
    def having_sub_domain(self):

        subdomain = tldextract.extract(self.url).subdomain

        dots = subdomain.count(".")

        if dots == 0:
            return -1

        elif dots == 1:
            return 0

        return 1

    # =========================================================
    # 8. SSLfinal_State
    # =========================================================
    def ssl_final_state(self):

        if self.url.startswith("https://"):
            return -1

        return 1

    # =========================================================
    # 9. Domain_registeration_length
    # =========================================================
    def domain_registration_length(self):

        try:

            domain = urlparse(self.url).netloc

            info = whois.whois(domain)

            creation = info.creation_date
            expiration = info.expiration_date

            if isinstance(creation, list):
             creation = creation[0]

            if isinstance(expiration, list):
             expiration = expiration[0]

            if creation and expiration:

                days = (expiration - creation).days

                if days >= 365:
                    return -1

                return 1

            return 0
        except Exception:
            return 0

    # =========================================================
    # 10. Favicon
    # =========================================================
    def favicon(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            favicon_patterns = [
                'rel="icon"',
                "rel='icon'",
                'rel="shortcut icon"',
                "rel='shortcut icon'",
                'rel="apple-touch-icon"'
            ]

            for pattern in favicon_patterns:
                if pattern in html:
                    return -1

            return 1

        except Exception:
            return 0

    # =========================================================
    # 11. port
    # =========================================================
    def port(self):

        try:
            port = self.parsed.port

            if port is None:
                return -1

            if port in [80, 443]:
                return -1

            return 1

        except Exception:
            return 0

    # =========================================================
    # 12. HTTPS_token
    # =========================================================
    def https_token(self):

        domain = self.domain

        # HTTPS appearing inside the domain can be suspicious.
        if "https" in domain:
            return 1

        return -1

    # =========================================================
    # 13. Request_URL
    # =========================================================
    def request_url(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            external_count = 0
            total_count = 0

            patterns = [
                r'<img[^>]+src=["\']([^"\']+)',
                r'<script[^>]+src=["\']([^"\']+)',
                r'<link[^>]+href=["\']([^"\']+)'
            ]

            for pattern in patterns:
                matches = re.findall(pattern, html)

                for link in matches:
                    total_count += 1

                    if link.startswith("http"):
                        link_domain = urlparse(link).netloc.lower()

                        if link_domain and self.domain not in link_domain:
                            external_count += 1

            if total_count == 0:
                return 0

            percentage = (external_count / total_count) * 100

            if percentage < 22:
                return -1

            elif percentage <= 61:
                return 0

            return 1

        except Exception:
            return 0

    # =========================================================
    # 14. URL_of_Anchor
    # =========================================================
    def url_of_anchor(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            links = re.findall(
                r'<a[^>]+href=["\']([^"\']*)',
                html
            )

            if not links:
                return 0

            suspicious = 0

            for link in links:

                if link in ["#", "", "javascript:void(0)"]:
                    suspicious += 1

                elif link.startswith("http"):
                    link_domain = urlparse(link).netloc.lower()

                    if link_domain and self.domain not in link_domain:
                        suspicious += 1

            percentage = (suspicious / len(links)) * 100

            if percentage < 31:
                return -1

            elif percentage <= 67:
                return 0

            return 1

        except Exception:
            return 0

    # =========================================================
    # 15. Links_in_tags
    # =========================================================
    def links_in_tags(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            links = re.findall(
                r'<link[^>]+href=["\']([^"\']*)',
                html
            )

            scripts = re.findall(
                r'<script[^>]+src=["\']([^"\']*)',
                html
            )

            total = len(links) + len(scripts)

            if total == 0:
                return 0

            external = 0

            for item in links + scripts:

                if item.startswith("http"):
                    item_domain = urlparse(item).netloc.lower()

                    if item_domain and self.domain not in item_domain:
                        external += 1

            percentage = (external / total) * 100

            if percentage < 17:
                return -1

            elif percentage <= 81:
                return 0

            return 1

        except Exception:
            return 0

    # =========================================================
    # 16. SFH
    # =========================================================
    def sfh(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            forms = re.findall(
                r'<form[^>]*action=["\']([^"\']*)',
                html
            )

            if not forms:
                return -1

            for action in forms:

                if action in ["", "about:blank"]:
                    return 1

                if action.startswith("http"):
                    action_domain = urlparse(action).netloc.lower()

                    if action_domain and self.domain not in action_domain:
                        return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # 17. Submitting_to_email
    # =========================================================
    def submitting_to_email(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            if "mailto:" in html:
                return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # 18. Abnormal_URL
    # =========================================================
    def abnormal_url(self):

        try:
            if self.having_ip_address() == 1:
                return 1

            if self.domain == "":
                return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # 19. Redirect
    # =========================================================
    def redirect(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True
            )

            redirects = len(response.history)

            if redirects == 0:
                return -1

            elif redirects <= 2:
                return 0

            return 1

        except Exception:
            return 0

    # =========================================================
    # 20. on_mouseover
    # =========================================================
    def on_mouseover(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            if "onmouseover" in html:
                return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # 21. RightClick
    # =========================================================
    def right_click(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            if "event.button==2" in html or "contextmenu" in html:
                return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # 22. popUpWidnow
    # =========================================================
    def popup_window(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            if "window.open" in html:
                return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # 23. Iframe
    # =========================================================
    def iframe(self):

        try:
            response = requests.get(
                self.url,
                timeout=5,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            html = response.text.lower()

            if "<iframe" in html or "<frame" in html:
                return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # 24. age_of_domain
    # =========================================================
    def age_of_domain(self):

        try:
            info = whois.whois(self.domain)

            creation = info.creation_date

            if isinstance(creation, list):
                creation = creation[0]

            if creation:
                from datetime import datetime

                age_days = (datetime.now() - creation).days

                if age_days >= 180:
                    return -1

                return 1

        except Exception:
            pass

        return 0

    # =========================================================
    # 25. DNSRecord
    # =========================================================
    def dns_record(self):

        try:
            socket.gethostbyname(self.domain)
            return -1

        except Exception:
            return 1

    # =========================================================
    # 26. web_traffic
    # =========================================================
    def web_traffic(self):

        # Without an external traffic-ranking API,
        # use a conservative neutral value.
        return 0

    # =========================================================
    # 27. Page_Rank
    # =========================================================
    def page_rank(self):

        # Google PageRank is no longer directly available
        # as a public API. Use neutral value for now.
        return 0

    # =========================================================
    # 28. Google_Index
    # =========================================================
    def google_index(self):

        # This requires a search engine/API check.
        # Use neutral value instead of guessing.
        return 0

    # =========================================================
    # 29. Links_pointing_to_page
    # =========================================================
    def links_pointing_to_page(self):

        # Requires external backlink/search API.
        # Neutral value for the first version.
        return 0

    # =========================================================
    # 30. Statistical_report
    # =========================================================
    def statistical_report(self):

        suspicious_ips = [
            "146.112.61.108",
            "103.224.212.222",
            "82.221.136.25"
        ]

        try:
            ip = socket.gethostbyname(self.domain)

            if ip in suspicious_ips:
                return 1

            return -1

        except Exception:
            return 0

    # =========================================================
    # Extract all 30 features
    # IMPORTANT: SAME ORDER AS DATASET
    # =========================================================
    def extract_features(self):

        features = [

            self.having_ip_address(),          # 1
            self.url_length(),                 # 2
            self.shortening_service(),         # 3
            self.having_at_symbol(),           # 4
            self.double_slash_redirecting(),   # 5
            self.prefix_suffix(),              # 6
            self.having_sub_domain(),          # 7
            self.ssl_final_state(),            # 8
            self.domain_registration_length(), # 9
            self.favicon(),                    # 10
            self.port(),                       # 11
            self.https_token(),                # 12
            self.request_url(),                # 13
            self.url_of_anchor(),              # 14
            self.links_in_tags(),              # 15
            self.sfh(),                        # 16
            self.submitting_to_email(),        # 17
            self.abnormal_url(),               # 18
            self.redirect(),                   # 19
            self.on_mouseover(),               # 20
            self.right_click(),                # 21
            self.popup_window(),               # 22
            self.iframe(),                     # 23
            self.age_of_domain(),              # 24
            self.dns_record(),                 # 25
            self.web_traffic(),                # 26
            self.page_rank(),                  # 27
            self.google_index(),               # 28
            self.links_pointing_to_page(),     # 29
            self.statistical_report()          # 30
        ]

        return features


# =============================================================
# TEST FEATURE EXTRACTOR
# =============================================================
if __name__ == "__main__":

    url = input("Enter URL: ")

    extractor = FeatureExtractor(url)

    features = extractor.extract_features()

    print("\nExtracted Features:")
    print(features)

    print("\nNumber of Features:")
    print(len(features))