from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import time
import logging
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_text_only(url):
    start_time = time.time()
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        logger.info(f"Fetching: {url}")
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove unwanted elements
        for element in soup(['script', 'style', 'noscript', 'iframe', 'svg', 
                           'nav', 'footer', 'header', 'form', 'img', 
                           'picture', 'video', 'audio', 'canvas']):
            element.decompose()

        text_content = soup.get_text(separator='\n', strip=True)
        clean_text = '\n'.join([line for line in text_content.split('\n') if line.strip()])

        return {
            "content": clean_text,
            "word_count": len(clean_text.split()),
            "status": "success",
            "processing_time": time.time() - start_time
        }

    except Exception as e:
        logger.error(f"Error extracting text: {str(e)}")
        return {
            "error": str(e),
            "status": "failed",
            "processing_time": time.time() - start_time
        }

def check_ips(ip_list, colorblind_mode=False):
    base_url = "https://www.bulkblacklist.com/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Origin': 'https://www.bulkblacklist.com',
        'Referer': 'https://www.bulkblacklist.com/'
    }

    session = requests.Session()
    
    try:
        # Handle colorblind mode toggle
        if colorblind_mode:
            toggle_url = "https://www.bulkblacklist.com/toggle-colorblind-mode"
            session.post(toggle_url, headers=headers)

        ips_text = "\n".join(ip_list)
        response = session.post(base_url, data={'ips': ips_text}, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', {'class': 'table'})
        if not table:
            raise ValueError("Results table not found")

        results = []
        for row in table.find_all('tr')[1:]:  # Skip header row
            cells = row.find_all('td')
            if len(cells) >= 8:
                results.append({
                    'ip': cells[1].get_text(strip=True),
                    'ptr_record': cells[2].get_text(strip=True),
                    'spamcop': 'Yes' if cells[3].get_text(strip=True) == '✓' else 'No',
                    'spamhaus': 'Yes' if cells[4].get_text(strip=True) == '✓' else 'No',
                    'barracuda': 'Yes' if cells[5].get_text(strip=True) == '✓' else 'No',
                    'sender_score': cells[6].get_text(strip=True),
                    'sender_base': cells[7].get_text(strip=True)
                })

        return {
            'status': 'success',
            'results': results,
            'ip_count': len(results),
            'colorblind_mode': colorblind_mode
        }

    except Exception as e:
        logger.error(f"Error checking IPs: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }
    finally:
        session.close()

@app.route('/extract', methods=['POST'])
def extract():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL required", "status": "failed"}), 400

    url = data['url'].strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = extract_text_only(url)
    return jsonify(result), 200 if result["status"] == "success" else 500

@app.route('/check-ips', methods=['POST'])
def check_ip_list():
    start_time = time.time()
    data = request.get_json()
    
    if not data or 'ips' not in data:
        return jsonify({
            'status': 'error',
            'message': 'IP list required',
            'processing_time': time.time() - start_time
        }), 400

    ip_list = data['ips']
    if not isinstance(ip_list, list):
        return jsonify({
            'status': 'error',
            'message': 'IPs must be provided as an array',
            'processing_time': time.time() - start_time
        }), 400

    colorblind_mode = data.get('colorblind_mode', False)
    result = check_ips(ip_list, colorblind_mode)
    result['processing_time'] = time.time() - start_time

    return jsonify(result), 200 if result['status'] == 'success' else 500

@app.route('/')
def home():
    return jsonify({
        "message": "API Service",
        "endpoints": {
            "/extract": {"method": "POST", "description": "Extract text from URL"},
            "/check-ips": {"method": "POST", "description": "Check IPs against blacklists"}
        }
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    app.run()
