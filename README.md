# 🔐 CyberPulse — IP Threat Intelligence Dashboard

A real-time cybersecurity dashboard that analyzes IP addresses 
and detects malicious activity using live threat intelligence data.

## Features
- 🗺️ Interactive world map with live IP geolocation
- 🔴 Risk scoring: CRITICAL / HIGH / MEDIUM / LOW
- 🧠 Attack type detection (DDoS, Brute Force, SQL Injection...)
- 📊 Real-time statistics dashboard
- 📄 PDF report export
- 🔊 Sound alerts for critical threats

## Tech Stack
- Python / Flask
- AbuseIPDB API
- Leaflet.js (interactive maps)
- JavaScript / HTML / CSS

## Setup
1. Clone the repo
2. Install dependencies: `pip install flask requests`
3. Add your AbuseIPDB API key in `app.py`
4. Run: `python app.py`
5. Open: `http://127.0.0.1:5000`
