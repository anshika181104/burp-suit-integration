import requests
from bs4 import BeautifulSoup
import re
import os
import datetime
import webbrowser 

TARGET = input("Enter target URL (e.g. http://testphp.vulnweb.com): ").strip()
PROXY = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
visited = set()
vulnerabilities = []

SENSITIVE_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",
    "Generic Card": r"\b[0-9]{13,16}\b",
    "Password in URL": r"(password|passwd)=\w+",
    "Token in URL": r"(sessionid|token|auth)=\w+"
}

CREDENTIALS = [("admin", "admin"), ("admin", "123456"), ("user", "password"), ("test", "test123")]


def extract_links(html, base):
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href.startswith("http"):
            links.add(href)
        elif href.startswith("/"):
            links.add(base.rstrip("/") + href)
    return links


def detect_sensitive_info(response_text, url):
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        if matches:
            vulnerabilities.append({
                "url": url,
                "type": label,
                "matches": list(set(matches))
            })


def detect_session_hijack(response, url):
    cookie_header = response.headers.get("Set-Cookie", "")
    issues = []
    if cookie_header:
        if "Secure" not in cookie_header:
            issues.append("Cookie missing Secure flag")
        if "HttpOnly" not in cookie_header:
            issues.append("Cookie missing HttpOnly flag")
    if re.search(r"(token|session)=\w+", url):
        issues.append("Session token found in URL")
    if issues:
        vulnerabilities.append({
            "url": url,
            "type": "Session Hijacking Risk",
            "matches": issues
        })


def detect_login_forms(response_text, url):
    soup = BeautifulSoup(response_text, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        if "login" in str(form).lower():
            print(f"[!] Login form found at {url}")
            return form
    return None


def test_brute_force(url):
    print(f"[!] Testing for weak login at: {url}")
    try:
        for username, password in CREDENTIALS:
            payload = {"username": username, "password": password}
            response = requests.post(url, data=payload, proxies=PROXY, verify=False, timeout=10)
            if "invalid" not in response.text.lower() and response.status_code == 200:
                vulnerabilities.append({
                    "url": url,
                    "type": "Weak Login Credentials",
                    "matches": [f"{username}:{password}"]
                })
                print(f"[+] Weak creds found: {username}:{password}")
                break
    except Exception as e:
        print(f"[x] Brute-force failed: {e}")


def test_sqli_xss(url):
    test_payloads = {
        "SQL Injection": ["' OR 1=1 --", "' UNION SELECT NULL--", "' AND sleep(5)--"],
        "XSS": ["<script>alert(1)</script>", "\" onmouseover=alert(1) x="]
    }

    try:
        parsed = requests.utils.urlparse(url)
        if "?" not in url or "=" not in url:
            return

        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        query = parsed.query

        for vuln_type, payloads in test_payloads.items():
            for payload in payloads:
                injected_query = "&".join(
                    f"{k.split('=')[0]}={payload}" for k in query.split("&") if "=" in k
                )
                injected_url = f"{base}?{injected_query}"

                print(f"[~] Testing {vuln_type}: {injected_url}")
                r = requests.get(injected_url, proxies=PROXY, verify=False, timeout=10)
                if "syntax" in r.text.lower() or "error" in r.text.lower() or "alert(1)" in r.text:
                    vulnerabilities.append({
                        "url": injected_url,
                        "type": vuln_type,
                        "matches": [payload]
                    })
                    print(f"[+] {vuln_type} detected at {injected_url}")
    except Exception as e:
        print(f"[x] Injection test failed: {e}")


def crawl(url, depth=2):
    if depth == 0 or url in visited:
        return
    try:
        visited.add(url)
        print(f"[~] Crawling {url}")
        response = requests.get(url, proxies=PROXY, verify=False, timeout=10)

        detect_sensitive_info(response.text, url)
        detect_session_hijack(response, url)
        form = detect_login_forms(response.text, url)
        if form:
            test_brute_force(url)

        test_sqli_xss(url)

        links = extract_links(response.text, url)
        for link in links:
            crawl(link, depth - 1)
    except Exception as e:
        print(f"[x] Error scanning {url}: {e}")


def generate_html_report():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"full_vuln_report_{timestamp}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"<html><head><title>Vulnerability Report</title></head><body>")
        f.write(f"<h1>🛡️ Full Vulnerability Scan Report</h1>")
        f.write(f"<p>Target: <strong>{TARGET}</strong></p>")
        f.write(f"<p>Scanned at: {timestamp}</p><hr>")

        if not vulnerabilities:
            f.write("<p>No vulnerabilities found ✅</p>")
        else:
            f.write(f"<h2>⚠️ {len(vulnerabilities)} Issues Found</h2>")
            for i, issue in enumerate(vulnerabilities, 1):
                f.write(f"<h3>{i}. {issue['type']}</h3>")
                f.write(f"<p><strong>URL:</strong> <a href='{issue['url']}'>{issue['url']}</a></p>")
                f.write(f"<p><strong>Details:</strong> {', '.join(issue['matches'])}</p>")
                f.write("<hr>")

        f.write("</body></html>")
    print(f"\n[+] HTML report saved as: {filename}")

    webbrowser.open('file://' + os.path.realpath(filename))


def main():
    print("[*] Starting full scan via Burp Proxy (Community Edition)...")
    crawl(TARGET)
    generate_html_report()
    print("[✓] Scan complete. Open the HTML report for details.")


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()