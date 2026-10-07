# CyberShield Analyzer — Project Report Draft

## Cover Page
**Project Title:** CyberShield Analyzer — Phishing URL Detection System & Log Analysis and Suspicious Activity Detection  
**Student:** [Name]  
**Guide/Trainer:** [Name]  
**Institute:** [Institute]  
**Submission Date:** [Date]

## Abstract
CyberShield Analyzer is a web-based cybersecurity analysis platform implementing two related defensive security tasks: phishing URL detection and suspicious activity detection from security logs. The first module accepts a URL, extracts structural indicators such as URL length, IP-address usage, HTTPS, suspicious keywords, subdomain depth and special characters, and applies an explainable rule-based risk score. The second module parses normalized security log entries and applies eight detection scenarios covering repeated failed logins, successful login after failures, multiple usernames from one source, restricted resource access, high request frequency, repeated error responses, flagged source IPs and unusual access hours. The application presents evidence, severity and summary information through a browser interface. The platform is packaged with Docker Compose so the frontend and FastAPI backend can be demonstrated consistently.

## 1. Introduction
Phishing URLs and suspicious login/request activity are common indicators of cyber attacks. A lightweight analysis platform can help students understand how security telemetry is converted into evidence and alerts.

## 2. Problem Statement
Build a system that classifies potentially phishing URLs and a system that analyzes system/application/security logs to identify unusual or potentially malicious activity.

## 3. Objectives
1. Extract meaningful URL features.
2. Produce an explainable URL risk classification.
3. Parse and normalize security log entries.
4. Detect at least eight suspicious activity scenarios.
5. Provide severity-based alerts and summary statistics.
6. Package the system for reproducible Docker deployment.

## 4. Scope
### In scope
URL structural analysis, sample labelled URL evaluation, normalized security logs, rule-based detection, alert generation, browser dashboard and Docker deployment.

### Out of scope
Live URL crawling, external reputation feeds, autonomous blocking, production SIEM integration and testing systems without authorization.

## 5. Existing System
Existing security products use reputation databases, threat intelligence, machine learning and SIEM correlation. This academic implementation focuses on transparent, explainable detection logic that can be understood during a viva.

## 6. Proposed System
The platform has two pipelines:
- URL → feature extraction → weighted rules → classification → reasons.
- Log file → parsing → grouping/correlation → detection rules → severity alerts → statistics.

## 7. System Requirements
- Docker Desktop / Docker Engine + Compose
- Python 3.12+ for local backend testing
- Node.js 22+ for local frontend development
- Modern browser
- Windows, Linux or macOS

## 8. Methodology / Implementation
### URL detection features
URL length, dot count, hyphen count, IP-address usage, HTTPS, suspicious keywords, subdomain count, special characters, ports, known shorteners and path patterns are extracted. Weighted rules convert these indicators into a risk score.

### Log detection rules
1. Repeated failed logins
2. Successful login after failures
3. Multiple usernames from one IP
4. Restricted resource access
5. High request frequency
6. Repeated 4xx/5xx responses
7. Flagged source IP
8. Activity outside the defined normal time window

## 9. Testing
Run:
```bash
python -m pytest tests -q
python evaluate.py
```

The repository includes 15 labelled URL test cases and a sample security log.

## 10. Results & Analysis
The evaluation script generates accuracy, precision, recall, F1-score and a confusion matrix. The current synthetic evaluation dataset is intended for demonstration and should not be presented as production detection performance.

## 11. Limitations
The URL engine is rule-based, the log parser expects the documented format, and the IP watchlist is a demonstration list rather than live intelligence. False positives and false negatives are possible.

## 12. Future Scope
Add ML models trained on larger legally obtained datasets, DNS/domain reputation, WHOIS-age signals, threat-intelligence APIs, streaming log ingestion, persistent storage, authentication, role-based access and SIEM integration.

## 13. Conclusion
CyberShield Analyzer demonstrates two practical defensive cybersecurity workflows in one deployable application. It provides explainable results and can be demonstrated consistently using Docker.

## References
Add the official documentation, dataset sources and papers actually used by the student. Do not claim references that were not consulted.
