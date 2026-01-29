import time
import subprocess
import re
import os
import sys
import socket
import threading
import json
from datetime import datetime
from collections import defaultdict, deque

# Configuration
LOG_FILE = '/logs/haproxy/haproxy.log'
BAN_THRESHOLD = 5  # Number of failures before ban
FIND_TIME = 60     # Time window in seconds
BAN_TIME = 3600    # Ban duration in seconds

# Regex patterns
# HAProxy log example: ... 192.168.1.1:1234 ...
IP_REGEX = r'^.*? (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

# Failure codes to watch
BAD_CODES = [' 401 ', ' 403 ', ' 429 ', ' 404 ']

# Paths that are safe to ignore even if they result in 404 (common for images/missing assets)
# case-insensitive search
IGNORE_PATHS = [
    '/UploadSanal/', 
    '/favicon.ico', 
    '.jpg', '.png', '.gif', '.css', '.js', '.woff'
]

# Paths that are definitely malicious tools/bots hunting for info
CRITICAL_PATHS = [
    '.env', '.git', 'wp-admin', 'wp-login', 'config.php', 
    '/api/.env', '/backend/.env', '/shell', '/admin/'
]

# Memory storage
ip_history = defaultdict(deque)

# Ban history database
BANS_DB_FILE = '/app/bans_history.json'

def load_bans_db():
    if os.path.exists(BANS_DB_FILE):
        try:
            with open(BANS_DB_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_ban_info(ip, reason):
    db = load_bans_db()
    db[ip] = {
        'reason': reason,
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    try:
        with open(BANS_DB_FILE, 'w') as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        log(f"Error saving ban info: {e}")

def log(msg):
    print(f"[GUARD] {msg}", flush=True)

def udp_syslog_server():
    IP = "0.0.0.0"
    PORT = 514
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((IP, PORT))
        log(f"Syslog Collector started on UDP {PORT}")
        
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                line = data.decode("utf-8").strip()
                # Append to log file
                with open(LOG_FILE, "a") as f:
                    f.write(line + "\n")
            except Exception as e:
                log(f"Error processing log packet: {e}")
    except Exception as e:
        log(f"Fatal UDP Server Error: {e}")
        sys.exit(1)

# Check threshold
WHITELIST_FILE = 'whitelist.txt'

def is_whitelisted(ip):
    # Hardcoded private ranges
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
         return True
    
    # Check whitelist file
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                for line in f:
                    line = line.strip().split('#')[0].strip() # Remove comments
                    if not line: continue
                    if ip == line:
                        return True
        except Exception as e:
            log(f"Error reading whitelist: {e}")
            
    return False

def ban_ip(ip, reason="Şüpheli aktivite (401/403/429/404)"):
    # Check whitelist
    if is_whitelisted(ip):
        log(f"IP {ip} is whitelisted. Skipping ban.")
        return

    # Check if already banned
    try:
        check = subprocess.run(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode == 0:
            return # Already banned
    except Exception:
        pass

    log(f"BANNING IP: {ip} (Reason: {reason})")
    
    try:
        subprocess.run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        # Save ban info to history
        save_ban_info(ip, reason)
    except subprocess.CalledProcessError as e:
        log(f"Error banning IP {ip}: {e}")

def process_line(line):
    # Quick check for bad codes and find which one
    detected_code = None
    for code in BAD_CODES:
        if code in line:
            detected_code = code.strip()
            break
    
    if not detected_code:
        return

    # Extract IP
    match_ip = re.search(IP_REGEX, line)
    if match_ip:
        ip = match_ip.group(1)
        now = time.time()
        
        # Extract Request Path
        request_path = "Bilinmiyor"
        match_req = re.search(r'"[A-Z]+\s+([^?\s]+)[^"]*"', line)
        if match_req:
            request_path = match_req.group(1)
        
        # --- SMART FILTERING ---
        lower_path = request_path.lower()
        
        # 1. Ignore 404s for common assets/uploads (False positives)
        if detected_code == '404':
            for ignore in IGNORE_PATHS:
                if ignore.lower() in lower_path:
                    # log(f"Ignored safe 404: {ip} -> {request_path}")
                    return

        # 2. Check for Critical Malicious Paths
        is_critical = False
        for critical in CRITICAL_PATHS:
            if critical.lower() in lower_path:
                is_critical = True
                break
        
        # Add to history (Critical paths count as BAN_THRESHOLD errors at once!)
        points = BAN_THRESHOLD if is_critical else 1
        
        for _ in range(points):
            ip_history[ip].append({
                'time': now,
                'code': detected_code,
                'path': request_path,
                'critical': is_critical
            })
        
        # Clean old entries
        while ip_history[ip] and ip_history[ip][0]['time'] < now - FIND_TIME:
            ip_history[ip].popleft()
            
        # Check threshold
        if len(ip_history[ip]) >= BAN_THRESHOLD:
            # Build detailed reason
            unique_codes = set()
            paths_count = {}
            total_critical = 0
            
            for item in ip_history[ip]:
                code = item['code'].strip()
                unique_codes.add(code)
                path = item['path']
                paths_count[path] = paths_count.get(path, 0) + 1
                if item.get('critical'): total_critical += 1
            
            # Smart Reason Generation
            reasons = []
            
            # 1. Check for Rate Limiting
            if '429' in unique_codes:
                reasons.append("Aşırı İstek (Rate Limit)")
            
            # 2. Check for Critical Paths
            if total_critical > 0:
                reasons.append("Yönetici Paneli/Hassas Dosya Taraması")
            
            # 3. Check for 403 (WAF or Access Denied)
            elif '403' in unique_codes:
                reasons.append("WAF/Erişim Engeli")
                
            # 4. Check for 404 (Scanning)
            elif '404' in unique_codes:
                reasons.append("Bot Taraması (Geçersiz Dosyalar)")
            
            # Combine main reason
            main_reason = " + ".join(reasons) if reasons else "Şüpheli Aktivite"
            
            # Add details
            top_paths = sorted(paths_count.items(), key=lambda x: x[1], reverse=True)[:3]
            path_summary = ", ".join([f"{p}" for p, count in top_paths])
            
            # Final formatted message
            full_reason = f"{main_reason} - Hedefler: {path_summary}"
            
            ban_ip(ip, full_reason)
            ip_history[ip].clear() 

def tail_file(filename):
    while not os.path.exists(filename):
        log(f"Waiting for log file: {filename}")
        time.sleep(5)

    f = open(filename, 'r')
    f.seek(0, 2) # Go to end

    while True:
        line = f.readline()
        if not line:
            try:
                if os.stat(filename).st_size < f.tell():
                    f.close()
                    f = open(filename, 'r')
                    f.seek(0, 0)
                else:
                    time.sleep(0.1)
            except FileNotFoundError:
                 time.sleep(1)
            continue
        
        process_line(line.strip())

if __name__ == "__main__":
    log("Starting Custom Guard Service...")
    
    # Ensure log directory exists
    log_dir = os.path.dirname(LOG_FILE)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Ensure log file exists
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()
        os.chmod(LOG_FILE, 0o666) # Make it writable

    # Start UDP Syslog Server in background
    t1 = threading.Thread(target=udp_syslog_server)
    t1.daemon = True
    t1.start()

    # Start HTTP API Server in background
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import json
    
    class GuardAPI(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/bans':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                # Get bans from iptables
                try:
                    res = subprocess.run(['iptables', '-L', 'INPUT', '-n', '--line-numbers'], capture_output=True, text=True)
                    lines = res.stdout.split('\n')
                    bans = []
                    bans_db = load_bans_db()  # Load ban history
                    
                    for line in lines:
                        if 'DROP' in line:
                            parts = line.split()
                            # Example parsing: num target prot opt source destination
                            # 1    DROP       all  --  1.2.3.4    0.0.0.0/0
                            if len(parts) >= 5:
                                ip = parts[4]
                                ban_info = bans_db.get(ip, {})
                                bans.append({
                                    'num': parts[0],
                                    'ip': ip,
                                    'reason': ban_info.get('reason', 'Şüpheli aktivite'),
                                    'date': ban_info.get('date', '-')
                                })
                    self.wfile.write(json.dumps({'bans': bans}).encode())
                except Exception as e:
                    self.wfile.write(json.dumps({'error': str(e)}).encode())
            
            elif self.path == '/whitelist':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                
                ips = []
                if os.path.exists(WHITELIST_FILE):
                     try:
                        with open(WHITELIST_FILE, 'r') as f:
                            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                     except: pass
                self.wfile.write(json.dumps({'whitelist': ips}).encode())

            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path == '/unban':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                try:
                    data = json.loads(post_data.decode('utf-8'))
                    ip = data.get('ip')
                    if ip:
                        # Exec unban
                        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'success', 'ip': ip}).encode())
                    else:
                        raise ValueError("IP missing")
                except Exception as e:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': str(e)}).encode())
            
            elif self.path == '/whitelist': # ADD Whitelist
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                try:
                    data = json.loads(post_data.decode('utf-8'))
                    ip = data.get('ip')
                    if ip:
                        # Append to file
                        with open(WHITELIST_FILE, 'a') as f:
                            f.write(f"{ip}\n")
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'added', 'ip': ip}).encode())
                    else:
                        raise ValueError("IP missing")
                except Exception as e:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': str(e)}).encode())

            elif self.path == '/unwhitelist': # REMOVE Whitelist
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                try:
                    data = json.loads(post_data.decode('utf-8'))
                    ip = data.get('ip')
                    if ip:
                        # Read All, Filter, Write Back
                        lines = []
                        if os.path.exists(WHITELIST_FILE):
                            with open(WHITELIST_FILE, 'r') as f:
                                lines = f.readlines()
                        
                        with open(WHITELIST_FILE, 'w') as f:
                            for line in lines:
                                if line.strip() != ip:
                                    f.write(line)
                        
                        self.send_response(200)
                        self.send_header('Content-type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'status': 'removed', 'ip': ip}).encode())
                    else:
                        raise ValueError("IP missing")
                except Exception as e:
                    self.send_response(500)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': str(e)}).encode())

            else:
                self.send_response(404)
                self.end_headers()

    def run_http_server():
        server_address = ('0.0.0.0', 5005)
        log(f"Guard Management API started on 0.0.0.0:5005")
        httpd = HTTPServer(server_address, GuardAPI)
        httpd.serve_forever()

    t2 = threading.Thread(target=run_http_server)
    t2.daemon = True
    t2.start()

    log(f"Watching {LOG_FILE}")
    try:
        tail_file(LOG_FILE)
    except KeyboardInterrupt:
        log("Stopping...")
