import sys
import os
from urllib.parse import urlparse

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from logic.blacklist_checker import check_blacklist
from logic.validator import validate_url

def test_specific_url():
    url = "https://verizon.egjdf.cc/pay/"
    print(f"Testing URL: {url}")
    
    # Simulate App Logic
    valid_url, error = validate_url(url)
    print(f"Validated URL: {valid_url}")
    
    parsed = urlparse(valid_url)
    hostname = parsed.netloc
    print(f"Extracted Hostname: '{hostname}'")
    
    result = check_blacklist(hostname)
    print(f"Blacklist Result: {result}")
    
    if result['listed']:
        print("SUCCESS: Domain is blacklisted.")
    else:
        print("FAILURE: Domain NOT blacklisted.")

if __name__ == "__main__":
    test_specific_url()
