import requests
from bs4 import BeautifulSoup
from urllib.parse import quote

email = input("Enter email: ")

url = "https://www.google.com/search?q=" + quote(f'"{email}"')

headers = {
    "User-Agent": "Mozilla/5.0"
}

response = requests.get(url, headers=headers)

soup = BeautifulSoup(response.text, "html.parser")

print("\nPublic results:\n")

for link in soup.find_all("a"):
    href = link.get("href")

    if href and href.startswith("http"):
        print(href)
