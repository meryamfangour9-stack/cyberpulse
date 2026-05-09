from flask import Flask, jsonify, render_template, request
import requests

app = Flask(__name__)

API_KEY = "cee8ac115f4c63b982f10b4b6eef80fc23d6200b787802df4f5c82e5f4b7284facd75d431b35103c"

ATTACK_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning", 
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH Attack",
    23: "IoT Targeted"
}
VT_API_KEY = "424f5c12cc3bc06786a0c32b70429fddb8806723f15a7823b4c830d7d24994d3"

def check_virustotal(ip):
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        )
        data = response.json()
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'vtScore': stats.get('malicious', 0) + stats.get('suspicious', 0)
        }
    except:
        return {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'vtScore': 0}

def get_risk_level(score):
    if score >= 90: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

def get_attack_types(reports):
    cats = set()
    for report in reports:
        for cat in report.get('categories', []):
            if cat in ATTACK_CATEGORIES:
                cats.add(ATTACK_CATEGORIES[cat])
    return list(cats)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/check')
def check_ip():
    ip = request.args.get('ip', '8.8.8.8')
    
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True
    }
    
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=10
        )
        data = response.json()
        
        if 'data' in data:
            d = data['data']
            d['riskLevel'] = get_risk_level(d.get('abuseConfidenceScore', 0))
            d['attackTypes'] = get_attack_types(d.get('reports', []))
            d['virusTotal'] = check_virustotal(ip)
            d['isMalicious'] = d.get('abuseConfidenceScore', 0) >= 50
            
        return jsonify(data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)