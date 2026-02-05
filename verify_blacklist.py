import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from logic.blacklist_checker import check_blacklist
from logic.scorer import calculate_risk_score

def test_blacklist_logic():
    print("Testing Blacklist Logic...")
    
    # Test 1: Phishing Domain (Critical)
    domain1 = "phishing-test.com"
    result1 = check_blacklist(domain1)
    print(f"Domain: {domain1}")
    print(f"Result: {result1}")
    assert result1['listed'] == True
    assert result1['category'] == "Phishing"
    assert result1['risk_level'] == "Critical"
    
    # Test 2: Safe Domain
    domain2 = "google.com"
    result2 = check_blacklist(domain2)
    print(f"Domain: {domain2}")
    print(f"Result: {result2}")
    assert result2['listed'] == False

    # Test 3: Scorer Logic (Critical)
    print("\nTesting Scorer...")
    # Provide safe defaults for other checks to isolate blacklist score
    check_results_critical = {
        'blacklist': result1,
        'domain_age': 365,
        'trust_pages': ['privacy', 'terms', 'contact', 'about']
    }
    score, label, reasons = calculate_risk_score(check_results_critical)
    print(f"Score for Critical: {score}, Label: {label}")
    print(f"Reasons: {reasons}")
    assert score >= 50
    assert "Critical Risk" in reasons[0]

    # Test 4: Scorer with Safe Domain
    check_results_safe = {
        'blacklist': result2,
        'domain_age': 365,
        'trust_pages': ['privacy', 'terms', 'contact', 'about']
    }
    score, label, reasons = calculate_risk_score(check_results_safe)
    print(f"Score for Safe: {score}")
    assert score == 0 # Should be 0 now

    print("\nVerification Passed!")

if __name__ == "__main__":
    test_blacklist_logic()
