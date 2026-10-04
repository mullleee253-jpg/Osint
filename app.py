from flask import Flask, request, jsonify
from flask_cors import CORS
import socket
import whois
import phonenumbers
from phonenumbers import geocoder, carrier
import requests
import re
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from collections import defaultdict
import asyncio
import aiohttp

app = Flask(__name__)
CORS(app)

# Кэш результатов
cache = {}
cache_ttl = timedelta(minutes=30)

# История поиска (в памяти)
user_history = defaultdict(list)

# Корреляции
data_correlations = defaultdict(set)

# Паттерны для распознавания
patterns = {
    'ip': re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
    'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    'phone': re.compile(r'^\+?[1-9]\d{1,14}$'),
    'domain': re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'),
    'url': re.compile(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'username': re.compile(r'^[a-zA-Z0-9_]{3,30}$')
}

def get_cache_key(data_type: str, value: str) -> str:
    return f"{data_type}:{value}"

def get_from_cache(data_type: str, value: str) -> Optional[dict]:
    key = get_cache_key(data_type, value)
    if key in cache:
        cached_data, timestamp = cache[key]
        if datetime.now() - timestamp < cache_ttl:
            return cached_data
        else:
            del cache[key]
    return None

def save_to_cache(data_type: str, value: str, data: dict):
    key = get_cache_key(data_type, value)
    cache[key] = (data, datetime.now())

def add_to_history(session_id: str, data_type: str, value: str, result: dict):
    user_history[session_id].append({
        'type': data_type,
        'value': value,
        'result': result,
        'timestamp': datetime.now().isoformat()
    })
    if len(user_history[session_id]) > 20:
        user_history[session_id].pop(0)

def add_correlation(session_id: str, data_type: str, value: str, related_data: dict):
    data_correlations[session_id].add((data_type, value))
    for key, val in related_data.items():
        if val and val != 'N/A':
            data_correlations[session_id].add((key, str(val)))

def detect_input_type(text: str) -> Tuple[str, str]:
    text = text.strip()
    
    if patterns['ip'].match(text):
        return 'ip', text
    elif patterns['email'].match(text):
        return 'email', text
    elif patterns['phone'].match(text):
        return 'phone', text
    elif patterns['domain'].match(text):
        return 'domain', text
    elif patterns['url'].match(text):
        return 'url', text
    elif patterns['username'].match(text):
        return 'username', text
    elif any(c.isdigit() for c in text) and '+' in text:
        return 'phone', text
    elif '.' in text and len(text.split('.')) > 1:
        return 'domain', text
    else:
        return 'name', text

@app.route('/api/ip', methods=['POST'])
def lookup_ip():
    data = request.json
    ip_address = data.get('ip')
    session_id = data.get('session_id', 'default')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    # Check cache
    cached = get_from_cache('ip', ip_address)
    if cached:
        add_to_history(session_id, 'ip', ip_address, cached)
        return jsonify(cached)
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        result = response.json()
        
        if result.get('status') == 'fail':
            return jsonify({'error': result.get('message', 'Failed to get info')}), 400
        
        formatted = {
            'type': 'ip',
            'value': ip_address,
            'country': result.get('country'),
            'countryCode': result.get('countryCode'),
            'region': result.get('regionName'),
            'city': result.get('city'),
            'lat': result.get('lat'),
            'lon': result.get('lon'),
            'timezone': result.get('timezone'),
            'isp': result.get('isp'),
            'org': result.get('org'),
            'as': result.get('as')
        }
        
        save_to_cache('ip', ip_address, formatted)
        add_to_history(session_id, 'ip', ip_address, formatted)
        add_correlation(session_id, 'ip', ip_address, result)
        
        return jsonify(formatted)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/domain', methods=['POST'])
def lookup_domain():
    data = request.json
    domain = data.get('domain')
    session_id = data.get('session_id', 'default')
    
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    cached = get_from_cache('domain', domain)
    if cached:
        add_to_history(session_id, 'domain', domain, cached)
        return jsonify(cached)
    
    try:
        ip = socket.gethostbyname(domain)
        domain_info = whois.whois(domain)
        
        formatted = {
            'type': 'domain',
            'value': domain,
            'ip': ip,
            'registrar': domain_info.get('registrar'),
            'created': str(domain_info.get('creation_date')) if domain_info.get('creation_date') else None,
            'expires': str(domain_info.get('expiration_date')) if domain_info.get('expiration_date') else None,
            'status': domain_info.get('status'),
            'name_servers': domain_info.get('name_servers')
        }
        
        save_to_cache('domain', domain, formatted)
        add_to_history(session_id, 'domain', domain, formatted)
        add_correlation(session_id, 'domain', domain, formatted)
        
        return jsonify(formatted)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/whois', methods=['POST'])
def lookup_whois():
    data = request.json
    domain = data.get('domain')
    session_id = data.get('session_id', 'default')
    
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    try:
        domain_info = whois.whois(domain)
        
        formatted = {
            'type': 'whois',
            'value': domain,
            'registrar': domain_info.get('registrar'),
            'registrar_id': domain_info.get('registrar_id'),
            'created': str(domain_info.get('creation_date')) if domain_info.get('creation_date') else None,
            'updated': str(domain_info.get('updated_date')) if domain_info.get('updated_date') else None,
            'expires': str(domain_info.get('expiration_date')) if domain_info.get('expiration_date') else None,
            'name': domain_info.get('name'),
            'org': domain_info.get('org'),
            'emails': domain_info.get('emails'),
            'country': domain_info.get('country'),
            'name_servers': domain_info.get('name_servers'),
            'status': domain_info.get('status'),
            'dnssec': domain_info.get('dnssec')
        }
        
        add_to_history(session_id, 'whois', domain, formatted)
        return jsonify(formatted)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dns', methods=['POST'])
def lookup_dns():
    data = request.json
    domain = data.get('domain')
    session_id = data.get('session_id', 'default')
    
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    try:
        a_records = socket.getaddrinfo(domain, None)
        a_ips = list(set([record[4][0] for record in a_records if record[0] == socket.AF_INET]))
        
        formatted = {
            'type': 'dns',
            'value': domain,
            'a_records': a_ips[:10]
        }
        
        add_to_history(session_id, 'dns', domain, formatted)
        return jsonify(formatted)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/email', methods=['POST'])
def check_email():
    data = request.json
    email = data.get('email')
    session_id = data.get('session_id', 'default')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    try:
        domain = email.split('@')[1]
        
        try:
            socket.getaddrinfo(domain, None)
            mx_status = True
        except:
            mx_status = False
        
        formatted = {
            'type': 'email',
            'value': email,
            'domain': domain,
            'mx_valid': mx_status
        }
        
        add_to_history(session_id, 'email', email, formatted)
        return jsonify(formatted)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/phone', methods=['POST'])
def lookup_phone():
    data = request.json
    phone = data.get('phone')
    session_id = data.get('session_id', 'default')
    
    if not phone:
        return jsonify({'error': 'Phone required'}), 400
    
    try:
        parsed = phonenumbers.parse(phone, None)
        
        formatted = {
            'type': 'phone',
            'value': phone,
            'valid': phonenumbers.is_valid_number(parsed),
            'country': geocoder.description_for_number(parsed, 'en'),
            'carrier': carrier.name_for_number(parsed, 'en')
        }
        
        save_to_cache('phone', phone, formatted)
        add_to_history(session_id, 'phone', phone, formatted)
        return jsonify(formatted)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/username', methods=['POST'])
def search_username():
    data = request.json
    username = data.get('username')
    session_id = data.get('session_id', 'default')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    platforms = {
        'Instagram': f'https://instagram.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'GitHub': f'https://github.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'TikTok': f'https://tiktok.com/@{username}',
        'YouTube': f'https://youtube.com/@{username}',
        'Telegram': f'https://t.me/{username}',
        'VK': f'https://vk.com/{username}'
    }
    
    formatted = {
        'type': 'username',
        'value': username,
        'platforms': platforms
    }
    
    add_to_history(session_id, 'username', username, formatted)
    return jsonify(formatted)

@app.route('/api/analyze', methods=['POST'])
def deep_analyze():
    data = request.json
    input_data = data.get('input')
    session_id = data.get('session_id', 'default')
    
    if not input_data:
        return jsonify({'error': 'Input required'}), 400
    
    data_type, value = detect_input_type(input_data)
    results = []
    
    if data_type == 'domain':
        try:
            ip = socket.gethostbyname(value)
            results.append({'key': 'IP', 'value': ip})
        except:
            pass
        try:
            domain_info = whois.whois(value)
            results.append({'key': 'Registrar', 'value': domain_info.get('registrar')})
            results.append({'key': 'Created', 'value': str(domain_info.get('creation_date'))})
        except:
            pass
    
    elif data_type == 'ip':
        try:
            response = requests.get(f'http://ip-api.com/json/{value}')
            ip_data = response.json()
            results.append({'key': 'Country', 'value': ip_data.get('country')})
            results.append({'key': 'ISP', 'value': ip_data.get('isp')})
        except:
            pass
    
    elif data_type == 'email':
        username = input_data.split('@')[0]
        domain = input_data.split('@')[1]
        results.append({'key': 'Username', 'value': username})
        results.append({'key': 'Domain', 'value': domain})
    
    # Correlations
    correlations = []
    for item in user_history[session_id]:
        if item['type'] != data_type and item['value'] != value:
            if value.lower() in str(item['value']).lower():
                correlations.append({'type': item['type'], 'value': item['value']})
    
    formatted = {
        'type': data_type,
        'value': value,
        'results': results,
        'correlations': correlations[:5]
    }
    
    add_to_history(session_id, f'analyze_{data_type}', value, formatted)
    return jsonify(formatted)

@app.route('/api/history', methods=['POST'])
def get_history():
    data = request.json
    session_id = data.get('session_id', 'default')
    
    history = user_history.get(session_id, [])
    return jsonify({'history': list(reversed(history[-10:]))})

@app.route('/api/correlations', methods=['POST'])
def get_correlations():
    data = request.json
    session_id = data.get('session_id', 'default')
    
    correlations = data_correlations.get(session_id, set())
    return jsonify({'correlations': [{'type': t, 'value': v} for t, v in list(correlations)[:20]]})

@app.route('/api/detect', methods=['POST'])
def detect_type():
    data = request.json
    input_data = data.get('input')
    
    if not input_data:
        return jsonify({'error': 'Input required'}), 400
    
    data_type, value = detect_input_type(input_data)
    return jsonify({'type': data_type, 'value': value})

@app.route('/')
def index():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
