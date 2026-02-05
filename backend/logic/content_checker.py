import requests
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

TRUST_PAGES = ['privacy', 'terms', 'contact', 'about']

def check_content_trust(url):
    """
    Checks for the presence of trust pages (Privacy Policy, Contact, etc.).
    Returns list of found pages.
    """
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)
        
        found_pages = []
        for page in TRUST_PAGES:
            for link in links:
                href = link['href'].lower()
                text = link.get_text().lower()
                if page in href or page in text:
                    found_pages.append(page)
                    break
        
        return found_pages
    except Exception as e:
        logger.error(f"Content check failed: {e}")
        return []
