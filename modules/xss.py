import requests
from bs4 import BeautifulSoup

def scan(url, user_agent=None, proxy=None):
    payload = "<script>alert(1337)</script>"
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            # Try query param XSS
            test_url = url
            if "?" in url:
                test_url += f"&xss={payload}"
            else:
                test_url += f"?xss={payload}"
            r = requests.get(test_url, headers=headers, proxies=proxies, timeout=10, verify=False)
            if payload in r.text:
                results.append({
                    "type": "XSS",
                    "endpoint": test_url,
                    "result": "VULNERABLE (HIGH)"
                })
            else:
                results.append({
                    "type": "XSS",
                    "endpoint": test_url,
                    "result": "SAFE"
                })
            return results
        for form in forms:
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            inputs = {i.get("name"): payload for i in form.find_all("input") if i.get("name")}
            target_url = action if action.startswith("http") else url.rstrip("/") + "/" + action.lstrip("/")
            if method == "post":
                r = requests.post(target_url, data=inputs, headers=headers, proxies=proxies, timeout=10, verify=False)
            else:
                r = requests.get(target_url, params=inputs, headers=headers, proxies=proxies, timeout=10, verify=False)
            if payload in r.text:
                results.append({
                    "type": "XSS",
                    "endpoint": target_url,
                    "result": "VULNERABLE (HIGH)"
                })
            else:
                results.append({
                    "type": "XSS",
                    "endpoint": target_url,
                    "result": "SAFE"
                })
    except Exception as e:
        results.append({
            "type": "XSS",
            "endpoint": url,
            "result": f"ERROR: {str(e)}"
        })
    return results 