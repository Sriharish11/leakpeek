import requests
from urllib.parse import urlparse, urljoin, urlencode

def scan(url, user_agent=None, proxy=None):
    params = ["redirect", "next", "url", "return", "continue", "redir", "go"]
    evil_url = "https://evil.com"
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    for param in params:
        test_url = url
        if "?" in url:
            test_url += f"&{param}={evil_url}"
        else:
            test_url += f"?{param}={evil_url}"
        try:
            resp = requests.get(test_url, headers=headers, proxies=proxies, allow_redirects=False, timeout=10, verify=False)
            location = resp.headers.get("Location", "")
            if evil_url in location:
                results.append({
                    "type": "Open Redirect",
                    "endpoint": test_url,
                    "result": "VULNERABLE (MEDIUM)"
                })
            else:
                results.append({
                    "type": "Open Redirect",
                    "endpoint": test_url,
                    "result": "SAFE"
                })
        except Exception as e:
            results.append({
                "type": "Open Redirect",
                "endpoint": test_url,
                "result": f"ERROR: {str(e)}"
            })
    return results 