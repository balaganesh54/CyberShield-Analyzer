# CyberShield Analyzer

A Docker-deployable academic cybersecurity platform implementing the two projects specified in the Cybersecurity Student Project Submission Guidelines:

1. **Phishing URL Detection System**
2. **Log Analysis & Suspicious Activity Detection**

## Features

### Project 1 — Phishing URL Detection
- Accepts a URL as input.
- Extracts URL length, dots, hyphens, IP-address usage, HTTPS, suspicious keywords, subdomain depth, special characters, URL shortener use, ports and path indicators.
- Uses an explainable rule-based scoring engine.
- Returns **Legitimate / Suspicious / Phishing**, severity, risk score and reasons.
- Includes 15 labelled test URLs and an evaluation script with accuracy, precision, recall, F1 and confusion matrix.

### Project 2 — Log Analysis
- Accepts UTF-8 `.log`/`.txt` files.
- Parses timestamp, source IP, username, event, status and path.
- Implements eight scenarios: repeated failed logins, successful login after failures, multiple usernames from one IP, restricted resource access, high request frequency, repeated 4xx/5xx responses, flagged source IP and unusual access hours.
- Produces severity-based alerts and summary statistics.
- Includes sample logs.

## Technology Stack
- Frontend: React + Vite + Lucide
- Backend: Python 3.12 + FastAPI + Pydantic
- Reverse proxy: Nginx
- Deployment: Docker + Docker Compose

## Run with Docker

Requirements: Docker Desktop with Compose.

```bash
docker compose up --build
```

Open:
- Web application: http://localhost:8080
- API health: http://localhost:8000/api/health

Stop:
```bash
docker compose down
```

## Run tests locally

From the project root:

```bash
python -m pip install -r backend/requirements.txt
python -m pytest tests -q
python evaluate.py
```

If pytest is not installed:
```bash
pip install pytest
```

## Sample Log Format

```text
2026-10-06 05:12:01 src=203.0.113.77 user=admin event=login status=401 path=/login
```

The complete sample is in `data/security.log`.

## API Endpoints

- `GET /api/health`
- `POST /api/url/analyze` — JSON: `{ "url": "https://example.com" }`
- `GET /api/url/test-dataset`
- `POST /api/logs/analyze` — multipart field: `file`
- `GET /api/logs/sample`

## Project Structure

```text
CyberShield_Analyzer/
├── README.md
├── docker-compose.yml
├── evaluate.py
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/main.py
├── frontend/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── package.json
│   ├── index.html
│   └── src/
├── data/
│   ├── url_test_cases.csv
│   └── security.log
├── tests/
│   └── test_project.py
├── models/
├── reports/
└── screenshots/
```

## Limitations

- The URL engine is a transparent rule-based detector, not a production-grade threat-intelligence service or ML model.
- URL classification is based on structural indicators and can produce false positives/negatives.
- The log parser expects the documented sample format.
- The flagged IP list is a demonstration watchlist only; it is not a live reputation feed.
- Use only authorized lab/test data and systems.

## Viva Explanation

The platform has two independent analysis pipelines. The URL pipeline parses a URL into measurable features and assigns weighted risk points to suspicious characteristics. The log pipeline normalizes each line into structured fields, groups events by source IP, then applies eight detection rules. Both pipelines return explainable evidence so the result can be demonstrated during a viva.

## Attribution / Academic Use

This implementation is structured specifically for the supplied project guidelines. Any external datasets, libraries or references added later should be cited in the final report. The project should be tested only with legally obtained data and authorized environments.
