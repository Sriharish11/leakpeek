import requests

def scan(url, user_agent=None, proxy=None):
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    try:
        resp = requests.get(url, headers=headers, proxies=proxies, timeout=10, verify=False)
        if "Index of /" in resp.text or "<title>Index of" in resp.text:
            results.append({
                "type": "Dir Listing",
                "endpoint": url,
                "result": "VULNERABLE (MEDIUM)"
            })
        else:
            results.append({
                "type": "Dir Listing",
                "endpoint": url,
                "result": "SAFE"
            })
    except Exception as e:
        results.append({
            "type": "Dir Listing",
            "endpoint": url,
            "result": f"ERROR: {str(e)}"
        })
    return results 