import whois
from datetime import datetime

domain = "google.com"
print(f"Checking {domain}...")
try:
    w = whois.whois(domain)
    print(f"Creation Date: {w.creation_date}")
    if w.creation_date:
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        print(f"Calculated Age: {(datetime.now() - creation_date).days}")
    else:
        print("No creation date found.")
except Exception as e:
    print(f"Error: {e}")
