import sys
sys.path.insert(0, 'backend')
from app.main import classify_url, parse_logs, analyze_logs

def test_legitimate_url():
    assert classify_url('https://www.google.com')['classification'] == 'Legitimate'

def test_phishing_url():
    assert classify_url('http://185.199.110.7/login')['classification'] == 'Phishing'

def test_log_parser():
    text='2026-10-06 05:12:01 src=203.0.113.77 user=admin event=login status=401 path=/login\n'
    assert len(parse_logs(text)) == 1

def test_failed_login_rule():
    text='\n'.join([f'2026-10-06 10:00:0{i} src=1.2.3.4 user=admin event=login status=401 path=/login' for i in range(4)])
    alerts,summary=analyze_logs(parse_logs(text))
    assert any(a['rule']=='Repeated failed logins' for a in alerts)
