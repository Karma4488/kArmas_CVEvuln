#!/usr/bin/env python3
"""
kArmas_CVEvuln - CVE Vulnerability Awareness Tool
Passive recon & public CVE lookup only.
Use ONLY on systems you own or have written authorization to assess.
"""

import requests
import sys
import json
import re
from urllib.parse import urlparse
from datetime import datetime

# ──────────────────────────────────────────────
BANNER = r"""
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░                                         ░
    ░    ██╗  ██╗ █████╗ ██████╗ ███╗   ███╗  ░
    ░    ██║ ██╔╝██╔══██╗██╔══██╗████╗ ████║  ░
    ░    █████╔╝ ███████║██████╔╝██╔████╔██║  ░
    ░    ██╔═██╗ ██╔══██║██╔══██╗██║╚██╔╝██║  ░
    ░    ██║  ██╗██║  ██║██║  ██║██║ ╚═╝ ██║  ░
    ░    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ░
    ░                                         ░
    ░       C V E v u l n  S c a n n e r     ░
    ░                                         ░
    ░   💀  kArmas_CVEvuln  v1.0  💀           ░
    ░   ☠️   Authorized Use Only  ☠️            ░
    ░                                         ░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

    💀💀💀  FOR AUTHORIZED TARGETS ONLY  💀💀💀
"""

SKULL = "💀"
WARN  = "☠️ "
OK    = "✅"
INFO  = "🔍"
ERR   = "❌"

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS   = {"User-Agent": "kArmas_CVEvuln/1.0 (authorized security research)"}

# ──────────────────────────────────────────────
TECH_CVE_KEYWORDS = {
    "apache":    ["Apache HTTP Server", "Apache"],
    "nginx":     ["nginx"],
    "php":       ["PHP"],
    "wordpress": ["WordPress"],
    "drupal":    ["Drupal"],
    "joomla":    ["Joomla"],
    "openssl":   ["OpenSSL"],
    "jquery":    ["jQuery"],
    "iis":       ["Microsoft IIS", "IIS"],
    "tomcat":    ["Apache Tomcat"],
    "flask":     ["Flask"],
    "django":    ["Django"],
    "laravel":   ["Laravel"],
    "express":   ["Express.js", "expressjs"],
    "spring":    ["Spring Framework"],
}

# ──────────────────────────────────────────────
def print_skull_divider():
    print(f"\n  {SKULL}{'─'*45}{SKULL}\n")

def normalize_url(target):
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target

def get_headers_passive(url):
    """Passive HTTP header grab — no crawling, no payloads."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        return r.headers, r.status_code
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url.replace("https://","http://"), headers=HEADERS, timeout=8)
            return r.headers, r.status_code
        except Exception as e:
            return None, str(e)
    except Exception as e:
        return None, str(e)

def detect_technologies(response_headers):
    """Detect tech stack from response headers."""
    detected = []
    server  = response_headers.get("Server", "").lower()
    powered = response_headers.get("X-Powered-By", "").lower()
    combined = server + " " + powered

    for tech, _ in TECH_CVE_KEYWORDS.items():
        if tech in combined:
            detected.append(tech)

    # Version extraction helper
    version_map = {}
    patterns = [
        (r"apache[/ ]([\d.]+)", "apache"),
        (r"nginx[/ ]([\d.]+)", "nginx"),
        (r"php[/ ]([\d.]+)", "php"),
    ]
    for pat, key in patterns:
        m = re.search(pat, combined)
        if m:
            version_map[key] = m.group(1)

    return detected, version_map, {
        "Server": response_headers.get("Server", "N/A"),
        "X-Powered-By": response_headers.get("X-Powered-By", "N/A"),
        "X-Frame-Options": response_headers.get("X-Frame-Options", "MISSING ⚠️"),
        "Content-Security-Policy": response_headers.get("Content-Security-Policy", "MISSING ⚠️"),
        "Strict-Transport-Security": response_headers.get("Strict-Transport-Security", "MISSING ⚠️"),
        "X-Content-Type-Options": response_headers.get("X-Content-Type-Options", "MISSING ⚠️"),
        "Referrer-Policy": response_headers.get("Referrer-Policy", "MISSING ⚠️"),
    }

def query_nvd(keyword, max_results=5):
    """Query NIST NVD public API for CVEs matching a keyword."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
        "startIndex": 0,
    }
    try:
        r = requests.get(NVD_API, params=params, timeout=12)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            results = []
            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "N/A")
                descs = cve.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d["lang"] == "en"), "No description.")
                metrics = cve.get("metrics", {})
                score = "N/A"
                severity = "N/A"
                for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss = metrics[metric_key][0].get("cvssData", {})
                        score    = cvss.get("baseScore", "N/A")
                        severity = cvss.get("baseSeverity", metrics[metric_key][0].get("baseSeverity","N/A"))
                        break
                results.append({
                    "id": cve_id,
                    "score": score,
                    "severity": severity,
                    "description": desc[:200] + ("..." if len(desc) > 200 else ""),
                })
            return results
        else:
            return []
    except Exception as e:
        print(f"  {ERR} NVD API error: {e}")
        return []

def severity_icon(severity):
    s = str(severity).upper()
    if s == "CRITICAL":  return f"{SKULL} CRITICAL"
    if s == "HIGH":      return f"{WARN} HIGH"
    if s == "MEDIUM":    return "⚠️  MEDIUM"
    if s == "LOW":       return "🔵 LOW"
    return f"❓ {severity}"

def print_security_header_analysis(header_info):
    print_skull_divider()
    print(f"  {INFO} SECURITY HEADER ANALYSIS\n")
    security_headers = [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    for h in security_headers:
        val = header_info.get(h, "MISSING ⚠️")
        icon = OK if "MISSING" not in str(val) else WARN
        print(f"  {icon}  {h}: {val}")

def scan(target, tech_overrides=None):
    print(BANNER)
    url = normalize_url(target)
    domain = urlparse(url).netloc
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"  {INFO} Target : {url}")
    print(f"  {INFO} Domain : {domain}")
    print(f"  {INFO} Time   : {ts}")
    print_skull_divider()

    # ── Step 1: Passive header grab
    print(f"  {SKULL} Grabbing HTTP headers (passive)...\n")
    resp_headers, status = get_headers_passive(url)

    if resp_headers is None:
        print(f"  {ERR} Could not reach target: {status}")
        sys.exit(1)

    print(f"  {OK} HTTP Status : {status}")

    detected, versions, header_info = detect_technologies(resp_headers)

    print(f"  {INFO} Server      : {header_info['Server']}")
    print(f"  {INFO} Powered-By  : {header_info['X-Powered-By']}")

    if detected:
        print(f"\n  {SKULL} Detected tech: {', '.join(detected)}")
    else:
        print(f"\n  {INFO} No tech fingerprinted from headers.")

    if tech_overrides:
        print(f"  {INFO} Manual overrides: {', '.join(tech_overrides)}")
        detected = list(set(detected + tech_overrides))

    # ── Step 2: Security headers
    print_security_header_analysis(header_info)

    # ── Step 3: CVE lookup
    if not detected:
        print(f"\n  {INFO} No technologies detected to look up CVEs for.")
        print(f"  {INFO} Use --tech <name> to manually specify (e.g. --tech wordpress php)")
    else:
        for tech in detected:
            keywords = TECH_CVE_KEYWORDS.get(tech, [tech])
            for kw in keywords[:1]:  # one query per tech
                print_skull_divider()
                print(f"  {SKULL} CVE Lookup → {kw.upper()}\n")
                version_hint = versions.get(tech)
                query = f"{kw} {version_hint}" if version_hint else kw
                cves = query_nvd(query, max_results=5)
                if not cves:
                    print(f"  {INFO} No public CVEs returned for '{query}' (NVD may be rate-limited).")
                else:
                    for c in cves:
                        sev = severity_icon(c["severity"])
                        print(f"  [{sev}]  {c['id']}  (Score: {c['score']})")
                        print(f"   └─ {c['description']}\n")

    # ── Footer
    print_skull_divider()
    print(f"  {SKULL}{SKULL}{SKULL}  SCAN COMPLETE  {SKULL}{SKULL}{SKULL}")
    print(f"\n  ⚠️  kArmas_CVEvuln performs PASSIVE recon + public CVE lookups only.")
    print(f"  ⚠️  Always obtain written authorization before scanning any target.")
    print(f"  ☠️  CVE data sourced from NIST NVD public API (nvd.nist.gov).")
    print_skull_divider()

# ──────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="kArmas_CVEvuln — CVE Awareness Scanner (authorized use only)"
    )
    parser.add_argument("target", help="Target URL or domain (e.g. example.com)")
    parser.add_argument(
        "--tech", nargs="+",
        help="Manually specify technologies to look up (e.g. --tech wordpress php nginx)"
    )
    args = parser.parse_args()
    scan(args.target, tech_overrides=args.tech)

if __name__ == "__main__":
    main()
