# Test-Feed

An open source cybersecurity threat feed aggregator. Pulls from free public RSS feeds, classifies articles into threat categories using keyword matching, and displays them in a clean web interface.

## Features

- Aggregates 10 top security RSS feeds automatically
- Classifies articles into: Cloud Breach, SaaS Breach, OT/ICS, Ransomware, Vulnerability/CVE
- Fetches new articles every 4 hours in the background
- Filterable web interface
- Zero API costs — regex based classification
- Railway ready with persistent SQLite storage

## Local Setup

**Requirements:** Python 3.8+

```bash
# Clone the repo
git clone https://github.com/YOURUSERNAME/test-feed.git
cd test-feed

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
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

Pull requests welcome. The easiest contribution is adding keywords to `categories.yml` to improve classification accuracy.

## License

MIT
