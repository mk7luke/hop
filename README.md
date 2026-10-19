# Hop

Paste a link. See each redirect, then copy the final address with tracking tags removed.

## Limits

- http and https only, port 80 and 443
- No private, local, or link-local addresses
- 6 hops, 4 seconds each, 30 checks per IP per hour
- Page scripts are not run. A meta refresh is shown and not opened.
- Not a safety check. Links are not stored.

## Run

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8884
```

Health: `GET /health`

MIT. Built on holy-hermes.
