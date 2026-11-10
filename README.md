# ThreatLens

Advanced phishing detection and threat intelligence platform built with Python, Flask and the VirusTotal API, with a companion Chrome extension.

## Features

- **URL scanner:** local phishing heuristics plus VirusTotal results
- **Domain, IP and file-hash scanners:** reputation lookups through VirusTotal
- **Optional file check:** files are hashed first; a file is uploaded only after explicit consent
- **Risk score from 0 to 100:** Low, Medium, High, Critical, or Unknown, with a breakdown of why
- **Scan history and reports:** saved in SQLite, with a downloadable JSON report
- **Dark web dashboard**
- **Chrome extension:** scan the current page, or right-click any link to check it without opening it

## Tech stack

Python, Flask, SQLite, VirusTotal API v3, HTML, CSS, JavaScript, Chrome Extension (Manifest V3), pytest

## Setup

```bash
git clone https://github.com/sandravnair04-cys/Threatlens.git
cd Threatlens
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Open `.env` and replace the placeholder with your own VirusTotal API key. Never commit this file.

```bash
python app.py
```

Then open http://127.0.0.1:5000

## Chrome extension

1. Open `chrome://extensions` in Chrome or Chromium.
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select the `extension` folder.
4. Keep the Flask server running while you use it.

## Tests

```bash
python -m pytest -q
```

The tests use simulated VirusTotal responses, so they need no API key.

## Security

- The API key stays on the server in `.env`
- Input validation on every scan type
- Parameterised SQL queries
- Content-Security-Policy and other security headers
- Per-IP rate limiting
- CORS limited to extension origins

## Limitations

- The risk score is a heuristic, not proof that something is safe or malicious.
- A free VirusTotal key allows 4 requests per minute and 500 per day, and must not be used in commercial products or services.
- There is no user login yet, and the delete button has no CSRF protection, so this is meant for local use.

## Disclaimer

ThreatLens is an educational project. Do not rely on it as your only protection.

Built by Sandra V Nair
