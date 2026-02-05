from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from logic.validator import validate_url, check_https_ssl
from logic.whois_checker import check_domain_age
from logic.pattern_checker import check_patterns
from logic.content_checker import check_content_trust
from logic.blacklist_checker import check_blacklist
from logic.scorer import calculate_risk_score
from urllib.parse import urlparse

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route("/analyze", methods=["POST"])
def analyze_url():
    """
    Analyze a given URL for scam risk.
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"]

    # 1. Validation
    valid_url, error = validate_url(url)
    if not valid_url:
        return jsonify({"error": error}), 400

    # Extract hostname for blacklist/whois
    parsed = urlparse(valid_url)
    hostname = parsed.netloc

    # 2. Parallel Checks (Conceptually, for now sequential)

    # HTTPS Check
    is_https, https_details = check_https_ssl(valid_url)

    # WHOIS Check
    age_days, creation_date = check_domain_age(hostname)

    # Pattern Check
    patterns = check_patterns(valid_url)

    # Content Check
    trust_pages = check_content_trust(valid_url)

    # Blacklist Check
    is_blacklisted = check_blacklist(hostname)

    # 3. Validation & Scoring
    check_results = {
        "blacklist": is_blacklisted,
        "domain_age": age_days,
        "https_valid": is_https,
        "patterns": patterns,
        "trust_pages": trust_pages,
    }

    score, label, reasons = calculate_risk_score(check_results)

    result = {
        "url": valid_url,
        "hostname": hostname,
        "riskScore": score,
        "label": label,
        "recommendation": (
            "Proceed with caution"
            if label == "Suspicious"
            else ("Avoid this site" if label == "Fraudulent" else "Safe to visit")
        ),
        "reasons": reasons,
        "checks": {
            "https": is_https,
            "domainAgeDays": age_days,
            "suspiciousPatterns": any(patterns.values()),
            "trustPagesFound": trust_pages,
            "blacklisted": (
                is_blacklisted.get("listed", False)
                if isinstance(is_blacklisted, dict)
                else is_blacklisted
            ),
            "blacklistDetails": is_blacklisted,
            "creationDate": creation_date,
        },
        "timestamp": "2026-02-05T10:30:00Z",  # TODO: Use real timestamp
    }

    return jsonify(result), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)
