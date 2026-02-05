import whois
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def check_domain_age(domain):
    """
    Checks the domain age in days.
    Returns (age_days, creation_date).
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return -1, None

        # Ensure creation_date is naive or make now() aware (better to make aware if possible, but simplest is make naive)
        if creation_date.tzinfo:
            creation_date = creation_date.replace(tzinfo=None)

        age_days = (datetime.now() - creation_date).days
        return age_days, creation_date.isoformat()
    except Exception as e:
        logger.error(f"WHOIS check failed for {domain}: {e}")
        return -1, None
