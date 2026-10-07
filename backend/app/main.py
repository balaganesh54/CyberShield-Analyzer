from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import ipaddress, re, csv, io
from collections import Counter, defaultdict
from datetime import datetime

app = FastAPI(title='CyberShield Analyzer', version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

SUSPICIOUS_WORDS = ['login','verify','verification','secure','account','update','password','signin','confirm','bank','wallet','payment','free','bonus','gift','urgent','crypto','support']
SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','is.gd','ow.ly','buff.ly','cutt.ly'}

class URLRequest(BaseModel):
    url: str

def extract_url_features(url: str):
    raw = url.strip()
    candidate = raw if re.match(r'^https?://', raw, re.I) else 'http://' + raw
    p = urlparse(candidate)
    host = p.hostname or ''
    path_query = (p.path or '') + (('?' + p.query) if p.query else '')
    try:
        ipaddress.ip_address(host)
        uses_ip = True
    except ValueError:
        uses_ip = False
    labels = host.split('.') if host else []
    keywords = [w for w in SUSPICIOUS_WORDS if w in raw.lower()]
    features = {
        'url_length': len(raw),
        'dot_count': raw.count('.'),
        'hyphen_count': raw.count('-'),
        'at_symbol': '@' in raw,
        'double_slash': '//' in p.path,
        'uses_ip': uses_ip,
        'https': p.scheme.lower() == 'https',
        'subdomain_count': max(0, len(labels)-2),
        'suspicious_keyword_count': len(keywords),
        'special_char_count': len(re.findall(r'[^A-Za-z0-9:/._?=&%-]', raw)),
        'has_port': p.port is not None,
        'is_shortener': host.lower() in SHORTENERS,
        'entropy_hint': len(set(raw)) / max(1, len(raw)),
        'host': host,
        'path': path_query,
        'keywords': keywords,
    }
    return features

def classify_url(url: str):
    f = extract_url_features(url)
    score = 0
    reasons = []
    if f['uses_ip']:
        score += 4; reasons.append('Uses an IP address instead of a domain name')
    if not f['https']:
        score += 1; reasons.append('Does not use HTTPS')
    if f['url_length'] > 90:
        score += 2; reasons.append('Unusually long URL')
    elif f['url_length'] > 60:
        score += 1; reasons.append('Long URL')
    if f['at_symbol']:
        score += 3; reasons.append('Contains @ symbol')
    if f['hyphen_count'] >= 3:
        score += 1; reasons.append('Multiple hyphens in URL')
    if f['subdomain_count'] >= 3:
        score += 2; reasons.append('Deep subdomain structure')
    if f['suspicious_keyword_count'] >= 1:
        score += min(3, f['suspicious_keyword_count']); reasons.append('Contains suspicious security/account keywords')
    if f['is_shortener']:
        score += 2; reasons.append('Uses a known URL shortener')
    if f['special_char_count'] >= 3:
        score += 1; reasons.append('Contains several unusual special characters')
    if f['double_slash']:
        score += 2; reasons.append('Contains a double-slash path pattern')
    if score >= 6:
        label, severity = 'Phishing', 'High'
    elif score >= 3:
        label, severity = 'Suspicious', 'Medium'
    else:
        label, severity = 'Legitimate', 'Low'
    return {'url': url, 'classification': label, 'severity': severity, 'risk_score': min(100, score*10), 'features': f, 'reasons': reasons or ['No strong suspicious indicators detected']}

@app.get('/api/health')
def health(): return {'status':'ok','service':'CyberShield Analyzer'}

@app.post('/api/url/analyze')
def analyze_url(req: URLRequest):
    if not req.url.strip(): raise HTTPException(400, 'URL is required')
    return classify_url(req.url)

@app.get('/api/url/test-dataset')
def url_dataset():
    rows=[]
    with open('/data/url_test_cases.csv', newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            result=classify_url(r['url']); result['expected']=r['expected']; rows.append(result)
    return {'count':len(rows),'results':rows}

LOG_PATTERNS = [
    ('Repeated failed logins', 'HIGH'),
    ('Successful login after failures', 'HIGH'),
    ('Multiple usernames from one IP', 'HIGH'),
    ('Restricted resource access', 'HIGH'),
    ('High request frequency', 'MEDIUM'),
    ('Repeated 4xx/5xx responses', 'MEDIUM'),
    ('Flagged source IP', 'HIGH'),
    ('Outside normal access hours', 'MEDIUM'),
]

LOG_RE = re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+src=(?P<src>\S+)\s+user=(?P<user>\S+)\s+event=(?P<event>\S+)\s+status=(?P<status>\d{3})\s+path=(?P<path>\S+)')

def parse_logs(text):
    entries=[]
    for line in text.splitlines():
        m=LOG_RE.search(line.strip())
        if m:
            d=m.groupdict(); d['status']=int(d['status']); entries.append(d)
    return entries

def analyze_logs(entries):
    alerts=[]
    by_ip=defaultdict(list); by_ip_user=defaultdict(set); status_counter=Counter(); event_counter=Counter()
    for e in entries:
        by_ip[e['src']].append(e); by_ip_user[e['src']].add(e['user']); status_counter[e['status']] += 1; event_counter[e['event']] += 1
    flagged_ips={'185.199.110.7','203.0.113.77'}
    for ip, rows in by_ip.items():
        failures=[r for r in rows if r['event']=='login' and r['status'] in (401,403)]
        successes=[r for r in rows if r['event']=='login' and r['status']==200]
        if len(failures)>=3:
            alerts.append({'rule':'Repeated failed logins','severity':'HIGH','source_ip':ip,'count':len(failures),'reason':f'{len(failures)} failed login attempts from the same IP'})
        if successes and failures:
            alerts.append({'rule':'Successful login after failures','severity':'HIGH','source_ip':ip,'count':len(successes),'reason':'A successful login occurred after failed attempts from the same source'})
        if len(by_ip_user[ip])>=3:
            alerts.append({'rule':'Multiple usernames from one IP','severity':'HIGH','source_ip':ip,'count':len(by_ip_user[ip]),'reason':'One source attempted multiple usernames'})
        if len(rows)>=6:
            alerts.append({'rule':'High request frequency','severity':'MEDIUM','source_ip':ip,'count':len(rows),'reason':'High volume of requests in the supplied log window'})
        if ip in flagged_ips:
            alerts.append({'rule':'Flagged source IP','severity':'HIGH','source_ip':ip,'count':len(rows),'reason':'Source IP appears in the configured demonstration watchlist'})
    for e in entries:
        if e['path'].startswith('/admin') or e['path'].startswith('/private'):
            if e['status'] in (401,403): alerts.append({'rule':'Restricted resource access','severity':'HIGH','source_ip':e['src'],'count':1,'reason':f'Access denied for restricted path {e["path"]}'})
        if e['status']>=400:
            # repeated error rule is aggregated below
            pass
        try:
            hour=datetime.fromisoformat(e['ts'].replace(' ','T')).hour
            if hour < 6 or hour >= 22:
                alerts.append({'rule':'Outside normal access hours','severity':'MEDIUM','source_ip':e['src'],'count':1,'reason':f'Activity occurred at {hour:02d}:xx outside 06:00–22:00'})
        except ValueError: pass
    error_count=sum(v for k,v in status_counter.items() if k>=400)
    if error_count>=4:
        alerts.append({'rule':'Repeated 4xx/5xx responses','severity':'MEDIUM','source_ip':'multiple','count':error_count,'reason':f'{error_count} error responses were observed'})
    return alerts, {'total_events':len(entries),'unique_ips':len(by_ip),'unique_users':len(set(e['user'] for e in entries)),'status_counts':dict(status_counter),'event_counts':dict(event_counter),'alerts':len(alerts)}

@app.post('/api/logs/analyze')
async def analyze_log_file(file: UploadFile=File(...)):
    raw=await file.read()
    try: text=raw.decode('utf-8')
    except UnicodeDecodeError: raise HTTPException(400,'Log file must be UTF-8 text')
    entries=parse_logs(text)
    if not entries: raise HTTPException(400,'No supported log entries found. Use the sample format in README.')
    alerts, summary=analyze_logs(entries)
    return {'filename':file.filename,'entries':entries,'alerts':alerts,'summary':summary}

@app.get('/api/logs/sample')
def sample_logs():
    with open('/data/security.log', encoding='utf-8') as f: text=f.read()
    entries=parse_logs(text); alerts,summary=analyze_logs(entries)
    return {'entries':entries,'alerts':alerts,'summary':summary}
