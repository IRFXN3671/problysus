# Currently Implemented Features

## Backend (Flask)
The backend API is running on `http://localhost:5000` and provides the core logic for scam detection.

### 1. API Endpoint
- **POST /analyze**: Accepts a JSON body `{"url": "..."}` and returns a detailed analysis.

### 2. URL Validation & Security
- **Format Validation**: Automatically adds `https://` if missing and validates URL structure.
- **HTTPS/SSL Check**: Verifies if the site uses a valid HTTPS connection and SSL certificate. Risk score increases if invalid.

### 3. Domain Analysis (WHOIS)
- **Domain Age Calculation**: Fetches the domain's creation date.
- **New Domain Detection**:
    - **High Risk**: Domain is < 30 days old (+25 risk score).
    - **Medium Risk**: Domain is < 180 days old (+10 risk score).
- **Bug Fix**: Correctly handles timezone-aware dates to prevent errors.

### 4. Suspicious Pattern Detection
- **Keyword Search**: Flags suspicious words like `verify`, `free`, `urgent`, `login`, `secure`.
- **TLD Check**: Flags potentially risky Top-Level Domains (TLDs) like `.tk`, `.xyz`, `.ml`.
- **IP-based URLs**: Flags URLs that are just IP addresses.
- **Excessive Hyphens**: Flags domains with too many hyphens.

### 5. Content Trust Analysis
- **Page Scraping**: Fetches the website content.
- **Trust Indicators**: Checks for the existence of key pages:
    - Privacy Policy
    - Terms & Conditions
    - Contact Us
    - About Us
- **Scoring**: Missing multiple trust pages increases the risk score.

### 6. Blacklist Check
- **Local Database**: Checks the domain against a local blacklist of known bad domains.
- **Penalty**: Direct +40 risk score if found.

### 7. Risk Scoring Engine
- **Weighted System**: Aggregates all checks into a final score (0-100).
- **Classification**:
    - **0-30**: Safe (Green)
    - **31-70**: Suspicious (Yellow/Orange)
    - **71-100**: Fraudulent (Red)

---

## Frontend (React + Vite)
The frontend is running on `http://localhost:5173`.

### 1. User Interface
- **Modern Design**: Dark mode with "glassmorphism" aesthetic and CSS animations.
- **Responsive**: Adapts to different screen sizes.

### 2. Components
- **URL Input**: Accepts URLs, disables while processing, and shows a loading spinner.
- **Result Card**:
    - **Visual Score**: Large colored circle showing the score.
    - **Progress Bar**: Visual representation of risk.
    - **Findings List**: Detailed bullet points explaining *why* a site got its score.
    - **Checklist**: Icons showing status of HTTPS, Blacklist, Domain Age, etc.

---

## Tech Stack
- **Backend**: Python, Flask, `python-whois`, `requests`, `beautifulsoup4`, `tldextract`.
- **Frontend**: React, Vite, Vanilla CSS (Variables).
