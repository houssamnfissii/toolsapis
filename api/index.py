from flask import Flask, request, jsonify
from flask_cors import CORS
from playwright.sync_api import sync_playwright
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

# ----------- Text Extraction Functions -----------
def extract_text_only(url):
    start_time = time.time()
    try:
        with sync_playwright() as p:
            # Launch browser with aggressive optimizations
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-images",
                    "--disable-stylesheets",
                    "--disable-fonts",
                    "--disable-javascript",
                    "--no-sandbox",
                    "--disable-dev-shm-usage"
                ]
            )
            
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                java_script_enabled=False,
                bypass_csp=True
            )
            
            # Block ALL non-essential resources
            def block_all(route):
                if route.request.resource_type not in {"document", "xhr", "fetch"}:
                    route.abort()
                else:
                    route.continue_()
            
            context.route("**/*", block_all)
            
            page = context.new_page()

            # Navigate with minimal waiting
            logger.info(f"Loading: {url}")
            page.goto(url, wait_until="domcontentloaded", timeout=15000)

            # Extract text immediately without scrolling
            logger.info("Extracting raw text...")
            text_content = page.evaluate("""() => {
                const removals = ['script', 'style', 'noscript', 'iframe', 
                                'svg', 'nav', 'footer', 'header', 'form',
                                'img', 'picture', 'video', 'audio', 'canvas'];
                
                removals.forEach(tag => {
                    document.querySelectorAll(tag).forEach(el => el.remove());
                });
                
                return document.body.innerText;
            }""")

            browser.close()

            # Fast text cleaning
            clean_text = '\n'.join([line.strip() for line in text_content.split('\n') if line.strip()])
            
            return {
                "content": clean_text,
                "word_count": len(clean_text.split()),
                "status": "success",
                "processing_time": time.time() - start_time
            }
            
    except Exception as e:
        return {
            "error": str(e),
            "status": "failed",
            "processing_time": time.time() - start_time
        }

# ----------- IP Blacklist Functions -----------
def get_colorblind_mode_status(session):
    try:
        response = session.get("https://www.bulkblacklist.com/")
        soup = BeautifulSoup(response.text, 'html.parser')
        checkbox = soup.find('input', {'id': 'colorblindMode'})
        if checkbox:
            return 'checked' in checkbox.attrs
        return False
    except Exception as e:
        logger.error(f"Error checking colorblind mode status: {str(e)}")
        return False

def toggle_colorblind_mode(session, desired_state):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Origin': 'https://www.bulkblacklist.com',
            'Referer': 'https://www.bulkblacklist.com/',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        # First get current state
        current_state = get_colorblind_mode_status(session)
        
        # Only toggle if needed
        if current_state != desired_state:
            response = session.post(
                "https://www.bulkblacklist.com/toggle-colorblind-mode",
                headers=headers
            )
            response.raise_for_status()
            return True
        return True
    except Exception as e:
        logger.error(f"Error toggling colorblind mode: {str(e)}")
        return False

def clean_value(text):
    text = text.strip()
    if not text or text == '✓':
        return 'No'
    if text.lower() == 'yes':
        return 'Yes'
    if text.lower() == 'no':
        return 'No'
    return text

def check_ips(ip_list, colorblind_mode=False):
    base_url = "https://www.bulkblacklist.com/"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Origin': 'https://www.bulkblacklist.com',
        'Referer': 'https://www.bulkblacklist.com/'
    }

    session = requests.Session()

    try:
        # Set colorblind mode if requested
        if colorblind_mode:
            logger.info("Setting colorblind mode as requested...")
            if not toggle_colorblind_mode(session, True):
                logger.warning("Could not set colorblind mode")

        ips_text = "\n".join(ip_list)
        form_data = {'ips': ips_text}

        logger.info(f"Submitting {len(ip_list)} IPs for checking...")
        response = session.post(base_url, data=form_data, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', {'class': 'table'})
        if not table:
            raise ValueError("Results table not found")

        rows = table.find_all('tr')
        if len(rows) < 2:
            raise ValueError("No data rows found")

        results = []
        for row in rows[1:]:
            cells = row.find_all('td')
            if len(cells) >= 8:
                row_data = {
                    'index': cells[0].get_text(strip=True),
                    'ip': cells[1].get_text(strip=True),
                    'ptr_record': cells[2].get_text(strip=True),
                    'spamcop': clean_value(cells[3].get_text()),
                    'spamhaus': clean_value(cells[4].get_text()),
                    'barracuda': clean_value(cells[5].get_text()),
                    'sender_score': cells[6].get_text(strip=True),
                    'sender_base': cells[7].get_text(strip=True),
                    'api': cells[8].get_text(strip=True) if len(cells) > 8 else 'N/A'
                }
                results.append(row_data)

        return {
            'status': 'success',
            'results': results,
            'ip_count': len(results),
            'colorblind_mode': colorblind_mode
        }

    except Exception as e:
        logger.error(f"Error processing IPs: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }
    finally:
        session.close()

# ----------- API Endpoints -----------
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
    try:
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

        if len(ip_list) == 0:
            return jsonify({
                'status': 'error',
                'message': 'No IP addresses provided',
                'processing_time': time.time() - start_time
            }), 400

        # Get colorblind mode preference if provided
        colorblind_mode = data.get('colorblind_mode', False)
        
        result = check_ips(ip_list, colorblind_mode)
        result['processing_time'] = time.time() - start_time

        status_code = 200 if result['status'] == 'success' else 500
        return jsonify(result), status_code

    except Exception as e:
        logger.error(f"Unexpected error in /check-ips: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error',
            'processing_time': time.time() - start_time
        }), 500

@app.route('/')
def home():
    return jsonify({
        "message": "Welcome to the API Service",
        "description": "This service provides text extraction and IP blacklist checking functionality",
        "endpoints": {
            "/extract": "POST - Extract text from a URL",
            "/check-ips": "POST - Check IPs against blacklists (with colorblind mode support)",
            "/health": "GET - Service health check"
        },
        "note": "The IP checking functionality uses bulkblacklist.com"
    })

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
