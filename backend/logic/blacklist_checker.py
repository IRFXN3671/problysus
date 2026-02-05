BLACKLIST = [
    "example-scam.com",
    "phishing-test.com",
    "evil-site.org"
]

def check_blacklist(hostname):
    """
    Checks if the hostname is in the blacklist.
    """
    return hostname in BLACKLIST
