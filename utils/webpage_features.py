import requests

from bs4 import BeautifulSoup


class WebpageFeatures:

    def __init__(self, url):

        self.url = url

        try:

            response = requests.get(url, timeout=5)

            self.html = response.text

            self.soup = BeautifulSoup(self.html, "lxml")

        except:

            self.html = ""

            self.soup = None

    def favicon(self):

        if self.soup is None:
            return 1

        icon = self.soup.find("link", rel=lambda x: x and "icon" in x.lower())

        if icon:

            return -1

        return 1
    
    def anchor_url(self):

        if self.soup is None:
            return 1

        links = self.soup.find_all("a")

        if len(links) == 0:
            return 1

        suspicious = 0

        for link in links:

            href = link.get("href")

            if href is None:

                continue

        if "#" in href or "javascript" in href.lower():

            suspicious += 1

        ratio = suspicious / len(links)

        if ratio < 0.31:
            return -1

        elif ratio <= 0.67:
            return 0

        else:
            return 1
        
    def request_url(self):

        if self.soup is None:
            return 1

        images = self.soup.find_all("img")

        if len(images) == 0:
            return -1

        external = 0

        for img in images:

            src = img.get("src")

        if src and src.startswith("http"):

            external += 1

        ratio = external / len(images)

        if ratio < 0.22:
            return -1

        elif ratio <= 0.61:
            return 0

        else:
            return 1
        
    def iframe(self):

        if self.soup is None:
            return 1

        iframe = self.soup.find_all("iframe")

        if len(iframe) == 0:

            return -1

        return 1
    
    def popup_window(self):

        if self.html == "":
            return 1

        if "alert(" in self.html:

            return 1

        return -1
    
    def extract_features(self):

        return [

            self.favicon(),

            self.anchor_url(),

            self.request_url(),

            self.iframe(),

            self.popup_window()

        ]
    
    def extract_features(self):

        return [

            self.favicon(),

            self.anchor_url(),

            self.request_url(),

            self.iframe(),

            self.popup_window()

        ]