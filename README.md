# ProblySUS 🔍

ProblySUS is a URL scam detection tool that analyzes websites and estimates fraud risk using security heuristics and domain signals.

Built with a Flask backend and a simple web frontend.

---

## Features

- Scam keyword detection
- Credential form detection
- Domain age analysis
- DNS behavior checks
- SSRF protection
- Risk scoring system
- Optional PostgreSQL logging

---

## Tech Stack

- Python + Flask
- BeautifulSoup + Requests
- HTML / CSS / JavaScript

---

## Installation

```bash
git clone https://github.com/IRFXN3671/problysus.git
cd problysus
python -m venv venv
venv\Scripts\activate   # or source venv/bin/activate
pip install flask flask-cors requests beautifulsoup4 psycopg dnspython python-dotenv
```

---

## Run

```bash
python app.py
```

Open:

```
frontend/index.html
```

---

## Risk Levels

| Score | Status |
|------|--------|
| 0–34 | SAFE |
| 35–74 | SUSPICIOUS |
| 75+ | FRAUD |

---

## Disclaimer

This is a research prototype and not a replacement for professional security tools.
