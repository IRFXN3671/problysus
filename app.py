from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import psycopg
import os
import socket
import ipaddress
import dns.resolver
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout

# -------------------------------------------------
# ENV + APP SETUP
# -------------------------------------------------
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

app = Flask(__name__)
CORS(app)
executor = ThreadPoolExecutor(max_workers=3)

# -------------------------------------------------
# DATABASE (OPTIONAL, NO POOL)
# -------------------------------------------------
def get_db_connection():
    if not DATABASE_URL:
        return None
    try:
        return psycopg.connect(DATABASE_URL, connect_timeout=5)
    except Exception as e:
        print("DB connection failed:", e)
        return None

def save_scan_result(url, domain, score, status, confidence):
    conn = get_db_connection()
    if not conn:
        return
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scan_results
                    (url, domain, risk_score, status, confidence, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (url, domain, score, status, confidence))
    except Exception as e:
        print("DB insert failed:", e)
    finally:
        conn.close()

# -------------------------------------------------
# URL NORMALIZATION
# -------------------------------------------------
def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")

# -------------------------------------------------
# SSRF PROTECTION
# -------------------------------------------------
def is_private_or_local(domain: str) -> bool:
    try:
        ip = socket.gethostbyname(domain)
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_link_local
        )
    except Exception:
        return True

# -------------------------------------------------
# TRUSTED DOMAINS
# -------------------------------------------------
TRUSTED_DOMAINS = {
    "amazon.com", "amazon.in",
    "google.com", "google.co.in",
    "facebook.com", "microsoft.com",
    "apple.com", "wikipedia.org",
    "instagram.com"
}

def trusted_domain_check(domain: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS)

# -------------------------------------------------
# URL SHORTENERS
# -------------------------------------------------
SHORTENERS = {"tinyurl.com", "bit.ly", "t.co", "goo.gl", "shorturl.at"}

def high_risk_service_check(domain: str) -> bool:
    return domain in SHORTENERS

# -------------------------------------------------
# SAFE CONTENT FETCH
# -------------------------------------------------
def fetch_content(url: str):
    try:
        r = requests.get(
            url,
            timeout=(3, 5),
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Range": "bytes=0-60000"
            }
        )
        if r.status_code != 200:
            return "", ""
        soup = BeautifulSoup(r.text, "html.parser")
        return soup.get_text(" ", strip=True), r.text.lower()
    except Exception:
        return "", ""

# -------------------------------------------------
# CERTIFICATE TRANSPARENCY (WHOIS REPLACEMENT)
# -------------------------------------------------
def get_domain_first_seen_days(domain: str):
    """
    Uses Certificate Transparency logs (crt.sh)
    to estimate domain age (FAST, public).
    """
    try:
        r = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            timeout=3
        )
        if r.status_code != 200:
            return None

        data = r.json()
        if not data:
            return None

        earliest = min(
            datetime.fromisoformat(entry["not_before"])
            for entry in data
            if "not_before" in entry
        )

        return (datetime.utcnow() - earliest).days
    except Exception:
        return None

# -------------------------------------------------
# DNS BEHAVIOR
# -------------------------------------------------
def dns_ttl_seconds(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=3)
        return answers.rrset.ttl
    except Exception:
        return None

# -------------------------------------------------
# CONTENT ANALYSIS
# -------------------------------------------------
def trust_signal_check(text: str) -> bool:
    signals = [
        "privacy policy", "terms of service",
        "refund policy", "©", "all rights reserved"
    ]
    text = text.lower()
    return any(s in text for s in signals)

def scam_keyword_count(text: str) -> int:
    keywords = [
        "verify immediately",
        "account suspended",
        "urgent action required",
        "confirm your identity",
        "login to continue",
        "limited time offer"
    ]
    text = text.lower()
    return sum(1 for k in keywords if k in text)

# -------------------------------------------------
# FEATURE EXTRACTION (CT-BASED)
# -------------------------------------------------
def extract_features(url, domain, text, html):
    ct_age = None if trusted_domain_check(domain) else get_domain_first_seen_days(domain)
    ttl = dns_ttl_seconds(domain)

    return {
        "thin_content": len(text) < 400,
        "no_https": not url.startswith("https://"),
        "scam_keywords": scam_keyword_count(text),
        "credential_form": 'type="password"' in html,
        "missing_trust": not trust_signal_check(text),

        # Certificate Transparency signals
        "very_young_domain": ct_age is not None and ct_age < 7,
        "young_domain": ct_age is not None and ct_age < 30,

        # DNS behavior
        "low_dns_ttl": ttl is not None and ttl < 300
    }

# -------------------------------------------------
# SCORING ENGINE
# -------------------------------------------------
def score_features(features):
    score = 0
    reasons = []

    if features["thin_content"]:
        score += 15
        reasons.append("Minimal website content")

    if features["no_https"]:
        score += 20
        reasons.append("No HTTPS encryption")

    if features["missing_trust"]:
        score += 10
        reasons.append("Missing trust/legal pages")

    if features["scam_keywords"]:
        score += features["scam_keywords"] * 15
        reasons.append("Scam language detected")

    if features["credential_form"]:
        score += 30
        reasons.append("Credential harvesting form detected")

    if features["very_young_domain"]:
        score += 40
        reasons.append("Very new domain (certificate age)")
    elif features["young_domain"]:
        score += 25
        reasons.append("Recently observed domain")

    if features["low_dns_ttl"]:
        score += 15
        reasons.append("Suspicious DNS TTL")

    return score, reasons

# -------------------------------------------------
# ANALYZE ENDPOINT
# -------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = normalize_url(data["url"])
    domain = urlparse(url).netloc

    if is_private_or_local(domain):
        return jsonify({
            "status": "BLOCKED",
            "confidence": 100,
            "reasons": ["Private or internal address blocked"]
        })

    if trusted_domain_check(domain):
        return jsonify({
            "url": url,
            "domain": domain,
            "risk_score": 0,
            "status": "SAFE",
            "confidence": 99,
            "reasons": ["Trusted domain"]
        })

    if high_risk_service_check(domain):
        return jsonify({
            "url": url,
            "domain": domain,
            "risk_score": 40,
            "status": "SUSPICIOUS",
            "confidence": 80,
            "reasons": ["URL shortening service detected"]
        })

    future = executor.submit(fetch_content, url)
    try:
        text, html = future.result(timeout=6)
    except FutureTimeout:
        text, html = "", ""

    features = extract_features(url, domain, text, html)
    score, reasons = score_features(features)

    if score >= 75:
        status = "FRAUD"
    elif score >= 35:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    confidence = min(99, max(50, score))

    save_scan_result(url, domain, score, status, confidence)

    return jsonify({
        "url": url,
        "domain": domain,
        "risk_score": score,
        "status": status,
        "confidence": confidence,
        "reasons": reasons
    })

# -------------------------------------------------
# HEALTH CHECK
# -------------------------------------------------
@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(debug=True)
