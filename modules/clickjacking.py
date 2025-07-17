import requests

def scan(url, user_agent=None, proxy=None):
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
        xfo = resp.headers.get("X-Frame-Options", "").lower()
        csp = resp.headers.get("Content-Security-Policy", "").lower()
        if (not xfo or xfo not in ["deny", "sameorigin"]) and ("frame-ancestors" not in csp):
            results.append({
                "type": "Clickjacking",
                "endpoint": url,
                "result": "VULNERABLE (MEDIUM)"
            })
        else:
            results.append({
                "type": "Clickjacking",
                "endpoint": url,
                "result": "SAFE"
            })
    except Exception as e:
        results.append({
            "type": "Clickjacking",
            "endpoint": url,
            "result": f"ERROR: {str(e)}"
        })
    return results 