def calculate_risk_score(check_results):
    """
    Calculates the final risk score based on check results.
    Returns (score, label, reasons).
    """
    score = 0
    reasons = []

    # Unpack results
    blacklist = check_results.get('blacklist', False)
    domain_age = check_results.get('domain_age', 0)
    https_valid = check_results.get('https_valid', True)
    patterns = check_results.get('patterns', {})
    trust_pages = check_results.get('trust_pages', [])

    # 1. Blacklist Check (+40)
    if blacklist:
        score += 40
        reasons.append("Domain is blacklisted")

    # 2. Domain Age Check
    # < 30 days -> +25
    # < 180 days -> +10 (Medium risk logic adjustment)
    if domain_age != -1:
        if domain_age < 30:
            score += 25
            reasons.append("Domain is very new (< 1 month)")
        elif domain_age < 180:
            score += 10
            reasons.append("Domain is relatively new (< 6 months)")
    # Optional: Add small penalty for unknown age? For MVP, ignore.

    # 3. HTTPS Check (+20)
    if not https_valid:
        score += 20
        reasons.append("Website does not use a valid HTTPS connection")

    # 4. Suspicious Patterns (+10-15)
    if patterns.get('keywords'):
        score += 15
        reasons.append(f"Suspicious keywords found: {', '.join(patterns['keywords'])}")
    
    if patterns.get('hyphens'):
        score += 10
        reasons.append("Domain name contains excessive hyphens")
    
    if patterns.get('suspicious_tld'):
        score += 10
        reasons.append("Domain uses a potentially risky TLD")
    
    if patterns.get('ip_based'):
        score += 15
        reasons.append("URL is IP-based (often used in phishing)")

    # 5. Trust Pages (+5-10 per missing page, max 20?)
    # Logic: Missing trust pages increases risk.
    required_pages = ['privacy', 'terms', 'contact', 'about']
    missing_pages = [page for page in required_pages if page not in trust_pages]
    
    if len(missing_pages) > 2:
        score += 10
        reasons.append("Missing multiple trust pages (Privacy, Terms, etc.)")

    # Clamp score
    score = min(100, score)

    # Determine Label
    if score <= 30:
        label = "Safe"
    elif score <= 70:
        label = "Suspicious"
    else:
        label = "Fraudulent"

    return score, label, reasons
