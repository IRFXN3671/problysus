import re
import tldextract

SUSPICIOUS_KEYWORDS = [
    "verify",
    "free",
    "urgent",
    "claim",
    "login",
    "secure",
    "account",
    "update",
    "banking",
]
SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work"]


def check_patterns(url):
    """
    Checks for suspicious patterns in the URL.
    Returns dict of findings.
    """
    extracted = tldextract.extract(url)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomain = extracted.subdomain
    hostname = f"{subdomain}.{domain}.{suffix}" if subdomain else f"{domain}.{suffix}"

    findings = {
        "keywords": [],
        "hyphens": False,
        "suspicious_tld": False,
        "ip_based": False,
    }

    # Check for keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain or keyword in subdomain:
            findings["keywords"].append(keyword)

    # Check for excessive hyphens
    if domain.count("-") > 2 or subdomain.count("-") > 2:
        findings["hyphens"] = True

    # Check TLD
    if suffix in SUSPICIOUS_TLDS:
        findings["suspicious_tld"] = True

    # Check if IP based
    # Simple regex for IP pattern
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(domain):
        findings["ip_based"] = True

    return findings
