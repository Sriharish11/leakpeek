import requests
import os

def scan(url, user_agent=None, proxy=None):
    wordlist_path = os.path.join(os.path.dirname(__file__), '../wordlists/weak_creds.txt')
    login_paths = ["/login", "/admin/login", "/user/login"]
    headers = {"User-Agent": user_agent} if user_agent else {}
    proxies = {"http": proxy, "https": proxy} if proxy else {}
    results = []
    try:
        with open(wordlist_path) as f:
            creds = [line.strip().split(":") for line in f if ":" in line]
        for login_path in login_paths:
            login_url = url.rstrip("/") + login_path
            for username, password in creds:
                data = {"username": username, "password": password}
                resp = requests.post(login_url, data=data, headers=headers, proxies=proxies, timeout=10, allow_redirects=False, verify=False)
                # Heuristic: if login redirects or sets a session cookie, assume success
                if resp.status_code in [302, 301] or "set-cookie" in resp.headers:
                    results.append({
                        "type": "Broken Auth",
                        "endpoint": login_url,
                        "result": f"VULNERABLE (HIGH): {username}:{password}"
                    })
                else:
                    results.append({
                        "type": "Broken Auth",
                        "endpoint": login_url,
                        "result": "SAFE"
                    })
    except Exception as e:
        results.append({
            "type": "Broken Auth",
            "endpoint": url,
            "result": f"ERROR: {str(e)}"
        })
    return results 