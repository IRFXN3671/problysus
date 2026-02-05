import requests
import json
import os
import csv
from urllib.parse import urlparse
from io import StringIO
import datetime

# Configuration
OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
DATA_FILE = os.path.join(
    os.path.dirname(__file__), "..", "data", "blacklist_sources.json"
)
MAX_ENTRIES = 5000  # Limit to avoid huge file


def load_database():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Database corrupted or unreadable ({e}). Creating new one.")
            return {"meta": {"last_updated": None}, "domains": {}}
    return {"meta": {"last_updated": None}, "domains": {}}


def save_database(data):
    data["meta"]["last_updated"] = datetime.datetime.now().isoformat()
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"Database saved with {len(data['domains'])} entries.")


def fetch_openphish():
    print("Fetching OpenPhish data...")
    try:
        response = requests.get(OPENPHISH_URL, timeout=10)
        if response.status_code == 200:
            urls = response.text.strip().split("\n")
            print(f"Fetched {len(urls)} URLs from OpenPhish.")
            return urls
    except Exception as e:
        print(f"Error fetching OpenPhish: {e}")
    return []


def fetch_urlhaus():
    print("Fetching URLHaus data...")
    try:
        response = requests.get(URLHAUS_URL, timeout=10)
        if response.status_code == 200:
            # URLHaus CSV keys: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            f = StringIO(response.text)
            reader = csv.reader(f)
            urls = []
            for row in reader:
                if row and len(row) > 2 and row[0].isdigit():  # Skip headers/comments
                    # Filter only online or recent? The feed is 'recent', so assume relevant.
                    urls.append(row[2])
            print(f"Fetched {len(urls)} URLs from URLHaus.")
            return urls
    except Exception as e:
        print(f"Error fetching URLHaus: {e}")
    return []


def extract_hostname(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return urlparse(url).netloc
    except:
        return None


def update_blacklist():
    db = load_database()
    current_domains = db.get("domains", {})

    # 1. OpenPhish
    op_urls = fetch_openphish()
    count = 0
    for url in op_urls:
        hostname = extract_hostname(url)
        if hostname and hostname not in current_domains:
            current_domains[hostname] = {
                "category": "Phishing",
                "source": "OpenPhish",
                "risk_level": "Critical",
            }
            count += 1
            if len(current_domains) >= MAX_ENTRIES:
                break
    print(f"Added {count} entries from OpenPhish.")

    # 2. URLHaus (if space permits)
    if len(current_domains) < MAX_ENTRIES:
        uh_urls = fetch_urlhaus()
        count = 0
        for url in uh_urls:
            hostname = extract_hostname(url)
            if hostname and hostname not in current_domains:
                current_domains[hostname] = {
                    "category": "Malware",
                    "source": "URLHaus",
                    "risk_level": "Critical",
                }
                count += 1
                if len(current_domains) >= MAX_ENTRIES:
                    break
        print(f"Added {count} entries from URLHaus.")

    db["domains"] = current_domains
    save_database(db)


if __name__ == "__main__":
    update_blacklist()
