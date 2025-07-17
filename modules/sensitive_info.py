import requests

def scan(url, user_agent=None, proxy=None):
    sensitive_paths = ["/.env", "/.git/config", "/backup.zip", "/db.sql", "/config.php.bak"]
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    for path in sensitive_paths:
        test_url = url.rstrip("/") + path
        try:
            resp = requests.get(test_url, headers=headers, proxies=proxies, timeout=10, verify=False)
            if resp.status_code == 200 and len(resp.text) > 0 and not resp.text.lower().startswith("<html"):
                results.append({
                    "type": "Sensitive Info",
                    "endpoint": test_url,
                    "result": "VULNERABLE (HIGH)"
                })
            else:
                results.append({
                    "type": "Sensitive Info",
                    "endpoint": test_url,
                    "result": "SAFE"
                })
        except Exception as e:
            results.append({
                "type": "Sensitive Info",
                "endpoint": test_url,
                "result": f"ERROR: {str(e)}"
            })
    return results 