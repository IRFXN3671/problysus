import json
import os

def load_blacklist():
    """
    Loads the blacklist from the JSON file.
    """
    try:
        # Construct path relative to this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(current_dir, '..', 'data', 'blacklist_sources.json')
        
        with open(data_path, 'r') as f:
            data = json.load(f)
            return data.get('domains', {})
    except Exception as e:
        print(f"Error loading blacklist: {e}")
        return {}

# Cache the blacklist in memory
BLACKLIST_DB = {}
LAST_LOADED = 0

def load_blacklist():
    """
    Loads the blacklist from the JSON file if it has changed.
    """
    global BLACKLIST_DB, LAST_LOADED
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(current_dir, '..', 'data', 'blacklist_sources.json')
        
        if not os.path.exists(data_path):
            return

        # Check modification time
        mtime = os.path.getmtime(data_path)
        if mtime > LAST_LOADED:
            # print(f"Reloading blacklist data (changed at {mtime})")
            with open(data_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                BLACKLIST_DB = data.get('domains', {})
                LAST_LOADED = mtime
    except Exception as e:
        print(f"Error loading blacklist: {e}")

# Initial load
load_blacklist()

def check_blacklist(hostname):
    """
    Checks if the hostname is in the blacklist.
    Returns a dict with status and details.
    """
    # Ensure data is up to date
    load_blacklist()

    if hostname in BLACKLIST_DB:
        entry = BLACKLIST_DB[hostname]
        return {
            "listed": True,
            "category": entry.get("category", "Uncategorized"),
            "source": entry.get("source", "Unknown"),
            "risk_level": entry.get("risk_level", "High")
        }
    
    return {
        "listed": False,
        "category": None,
        "source": None,
        "risk_level": None
    }

