import requests

def scan(url, user_agent=None, proxy=None):
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
        sec_headers = {
            "Content-Security-Policy": "Missing CSP",
            "X-Frame-Options": "Missing X-Frame-Options",
            "Strict-Transport-Security": "Missing HSTS",
            "X-Content-Type-Options": "Missing X-Content-Type-Options",
            "Referrer-Policy": "Missing Referrer-Policy",
            "Permissions-Policy": "Missing Permissions-Policy"
        }
        for h, msg in sec_headers.items():
            if h not in resp.headers:
                results.append({
                    "type": "Sec Headers",
                    "endpoint": url,
                    "result": msg
                })
        if not results:
            results.append({
                "type": "Sec Headers",
                "endpoint": url,
                "result": "SAFE"
            })
    except Exception as e:
        results.append({
            "type": "Sec Headers",
            "endpoint": url,
            "result": f"ERROR: {str(e)}"
        })
    return results 