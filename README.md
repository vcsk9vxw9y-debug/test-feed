# Threat-Feed

An open source cybersecurity threat feed aggregator. Pulls from free public RSS feeds, classifies articles into threat categories using keyword matching, and displays them in a clean web interface.

## Features

- Aggregates 40+ security RSS feeds automatically
- Classifies articles into 14 categories: Cloud Breach, SaaS Breach, OT/ICS, Ransomware, Identity & Access, Vulnerability/CVE, Nation State/APT, Malware/Infostealer, AI Security, Phishing & Social Engineering, Supply Chain, Mobile Security, Industry/Policy, Uncategorized
- Word-boundary regex classification with priority ordering — zero API costs
- Tiered fetch schedule: priority sources (government CERTs, top threat-intel teams) hourly, secondary sources every 2h, community feeds every 4h
- Rate-limited JSON API (`/api/articles`, `/api/categories`, `/api/top-story`)
- Strict CSP + HSTS + security headers on every response
- Keyboard-navigable, accessible frontend (prefers-reduced-motion, prefers-contrast)
- Railway-ready with persistent SQLite storage and one-time data migrations

## Local Setup

**Requirements:** Python 3.8+

```bash
# Clone the repo
git clone https://github.com/YOURUSERNAME/test-feed.git
cd test-feed

# Install dependencies
pip install -r requirements.txt

# Run the app
python3 app.py
```

Open `http://localhost:5000` in your browser. The first fetch runs on startup and takes about 30-60 seconds.

## Adding RSS Feeds

Edit `scheduler.py` and add a new entry to the `FEEDS` list:

```python
{"url": "https://example.com/feed.xml", "name": "Source Name"},
```

## Adding or Editing Keywords

Edit `categories.yml` — no code changes needed. Add keywords under any existing category or create a new one. Restart the app after changes.

Example:
```yaml
Cloud Breach:
  - aws
  - your new keyword here
```

## Category Priority

Classification is first-match-wins in priority order. Threat categories rank ahead of context categories — a "CISA advisory on new ransomware gang" matches **Ransomware** first, not **Industry/Policy**. To change priority, edit the `priority` list in `classifier.py`.

## Data Migrations

One-time reclassification runs on startup and is gated by the `migrations` table so it never re-runs. See `reclassify_uncategorized_v1` / `_v2` in `app.py` for the pattern — add a new gated block after future keyword expansions, then remove the old block one release later.

## Railway Deployment

1. Push this repo to GitHub
2. Go to [railway.app](https://railway.app) and sign in with GitHub
3. New Project → Deploy from GitHub repo → select `test-feed`
4. In Railway settings, add a **Volume** mounted at `/data` for persistent SQLite storage
5. Railway will auto-deploy on every push to main

## Project Structure

```
test-feed/
  ├── app.py              # Flask app and API routes
  ├── scheduler.py        # RSS fetcher and feed list
  ├── classifier.py       # Regex keyword classifier
  ├── categories.yml      # Keyword lists per category
  ├── requirements.txt
  ├── Procfile
  ├── .gitignore
  ├── README.md
  ├── templates/
  │     └── index.html    # Frontend layout
  └── static/
        ├── style.css     # Styles
        └── main.js       # Frontend logic
```

## Contributing

Pull requests welcome. The easiest contribution is adding keywords to `categories.yml` to improve classification accuracy. Aegis — an agent currently in development — helps maintain the keyword lists and suggest category refinements.

## License

MIT
