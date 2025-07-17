import requests
from bs4 import BeautifulSoup

def scan(url, user_agent=None, proxy=None):
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            has_token = False
            for i in inputs:
                name = i.get("name", "").lower()
                if "csrf" in name or "token" in name:
                    has_token = True
                    break
            if has_token:
                results.append({
                    "type": "CSRF",
                    "endpoint": url,
                    "result": "SAFE"
                })
            else:
                results.append({
                    "type": "CSRF",
                    "endpoint": url,
                    "result": "VULNERABLE (HIGH)"
                })
        if not forms:
            results.append({
                "type": "CSRF",
                "endpoint": url,
                "result": "No forms found"
            })
    except Exception as e:
        results.append({
            "type": "CSRF",
            "endpoint": url,
            "result": f"ERROR: {str(e)}"
        })
    return results 