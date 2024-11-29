import re
import requests
from urllib.parse import urlparse

BLACKLISTED_DOMAINS = [
    "example-phishing.com",
    "malicious-site.net",
    "fake-login-page.org"
]

def check_blacklist(url):
    domain = urlparse(url).netloc
    return domain in BLACKLISTED_DOMAINS

def check_suspicious_patterns(url):
    patterns = [
        re.compile(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\.[a-zA-Z]{2,}"),
        re.compile(r"\d+\.\d+\.\d+\.\d+"),
        re.compile(r"https?://.*@"),
        re.compile(r"https?://(?:www\.)?(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}"),
        re.compile(r"https?://[^/]*\.[a-z]{2,}/[^ ]*[^/]+\.(exe|zip|rar|scr|bat)")
    ]
    for pattern in patterns:
        if pattern.search(url):
            return True
    return False

def phishing_link_scanner(url):
    if check_blacklist(url):
        return "⚠️ Warning: This URL is in the blacklist!"
    elif check_suspicious_patterns(url):
        return "⚠️ Warning: This URL contains suspicious patterns!"
    else:
        return "✅ Safe: No issues detected with this URL."

if __name__ == "__main__":
    test_url = input("Enter the URL to scan: ")
    result = phishing_link_scanner(test_url)
    print(result)
