🔍 LeakPeek — Modular CLI Web Vulnerability Scanner for Pentesters & Recon Experts
LeakPeek is a fast, modular, and visually-enhanced command-line tool built for web security testing. Designed for offensive security, bug bounty hunting, and real-world recon, it automates scanning for high-impact vulnerabilities like XSS, Open Redirects, CSRF flaws, missing security headers, and sensitive information leaks.

From lightweight audits to deeper reconnaissance, LeakPeek delivers clarity, speed, and actionable output — all from your terminal.

🎯 What Can LeakPeek Detect?
🔒 Bug Type	🔍 What It Checks	🚨 Risk
✅ Open Redirects	URL-based redirection using parameters like ?next= or ?url=	Medium
✅ Reflected XSS	Script injection in query parameters or input fields	High
✅ CSRF Token Checks	Detects missing or predictable CSRF protections in forms	Medium
✅ Clickjacking	Scans for missing X-Frame-Options headers	Low-Medium
✅ Security Headers	Validates presence of CSP, HSTS, XCTO, etc.	Best Practice
✅ Directory Listing	Auto-scans common open folders (/uploads/, /backup/, etc.)	Medium
✅ Sensitive Info	Searches for exposed .git, .env, debug traces, or API keys	High
✅ Broken Auth (safe)	Tests weak/default creds (if in-scope)	Critical

💻 Key Features
🎨 Visual CLI Output – Built with rich for stunning tables and status indicators

🔗 Modular Engine – Enable/disable any scan module via CLI

🚀 Multi-Threaded Scanning – Fast performance across multiple endpoints

📁 Custom Wordlist Support – Use your own fuzz lists for directories or parameters

📊 Report Output – Export findings to .csv, .json, or .md

🌐 Proxy Support – Easily route traffic through Burp or ZAP

⚙️ Built for Linux – Tested on Kali Linux 2025.2 and above

🧪 Sample Usage
bash
Copy
Edit
python3 leakpeek.py --url https://target.com --modules all --output report.csv
Custom scan:

bash
Copy
Edit
python3 leakpeek.py --url-list urls.txt --modules xss,redirects,headers --threads 20
Use with proxy:

bash
Copy
Edit
python3 leakpeek.py --url https://target.com --proxy http://127.0.0.1:8080
📂 Project Structure
graphql
Copy
Edit
LeakPeek/
├── leakpeek.py           # Main CLI entry point
├── modules/
│   ├── xss.py
│   ├── open_redirect.py
│   ├── csrf.py
│   ├── headers.py
│   ├── info_leak.py
│   └── ...
├── payloads/
│   ├── xss.txt
│   ├── redirect_params.txt
├── reports/
│   ├── report.csv
├── wordlists/
│   ├── directories.txt
│   ├── weak_creds.txt
├── README.md
└── LICENSE
🚧 Roadmap (2025.x Goals)
✅ DOM-based XSS detection

✅ Token discovery in JavaScript files

✅ OAuth misconfig checks

✅ OpenAPI/Swagger parser for endpoint fuzzing

✅ Report generation in Markdown

🔄 Optional Txxxx mapping (MITRE ATT&CK) for each scan type

⚠️ Legal & Ethical Use Only
LeakPeek is developed for authorized security testing, educational use, bug bounty programs, and lab environments.
Do NOT scan targets without explicit permission.

✨ Contribute
Pull requests welcome! If you'd like to add new modules, improve scan accuracy, or contribute wordlists, fork this repo and send your PR. Let’s build together.

🛡️ About
Built with ❤️ for hackers, students, and pros by offensive security minds.
Inspired by real recon workflows, bug bounty experience, and the Kali Linux ecosystem.
