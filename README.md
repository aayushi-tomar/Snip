# Snip
# URL Shortener

A URL shortener built with Python, Flask, and SQLite — with a safety check that
blocks known-malicious URLs before shortening them.

## Features
- Shorten any valid URL into a short code
- Redirect from short code to the original URL
- Persistent storage (SQLite)
- Collision-safe code generation
- Safety check before shortening (blocks known-malicious URLs)

## Run it locally

```bash
pip install -r requirements.txt
python app.py
```

Server runs at `http://localhost:5000`.

## Usage

**Shorten a URL:**
```bash
curl -X POST http://localhost:5000/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/some/very/long/path"}'
```

Response:
```json
{"code": "aB3x9k", "short_url": "http://localhost:5000/aB3x9k"}
```

**Visit the short link:**
```
http://localhost:5000/aB3x9k
```
Redirects to the original URL.

## What I'd add next
- Swap the placeholder safety check for a real Google Safe Browsing / VirusTotal API call
- Rate limiting per IP
- Click analytics
- Custom aliases
- Automated tests with pytest

## Why the safety check matters
Most beginner URL shorteners accept any input blindly. This one validates the URL
against a safety check first and rejects known-malicious links — the kind of
guardrail that matters once a service like this is public-facing.
