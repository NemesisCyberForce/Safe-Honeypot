# ============================================================================
#               N E M E S I S   C Y B E R   F O R C E # #
# ============================================================================
#
#  Blue Team Repository 
# ----------------------------------------------------
# This project is dedicated to Defensive Security (Blue Team).
# Its a TRAP!
# We focus on **Monitoring, Detection, and Defense**. Not RED!
# Red & Black is not public :P Learn to defend not to brick!
# We will not publish offensive security tools or weapons.
# 
# Based on the Idea to Defend: 
# Link: https://github.com/VolkanSah/HoneyPot-Worm
# Learn creating your own Honeypot, have a look in this repo ;)
# 
# --- PROJECT: Enhanced Passive Honeypot (Trap) ---
# An Enhanced Passive Honeypot (Trap) against unwanted users
# 
#  CRITICAL PRODUCTION WARNING AND DISCLAIMER!
# 
# This code is designed for **experienced security professionals** and is intended
# for deployment in controlled, monitored security environments.
# 
#  DANGER OF SELF-LOCKOUT:
# The **AUTO_BLOCK** feature utilizes system-level commands (iptables). If your
# **WHITELIST_IPS** are incomplete or incorrect, you **WILL** permanently block
# your own access to the server. Never deploy this without a working recovery plan.
# 
#  LEGAL NOTE:
# Using IP blocking and collecting attack data may be subject to strict data
# protection and surveillance laws in your region. Ensure full compliance with
# GDPR, CCPA, or other applicable regulations **BEFORE** deployment.
# 
# --- Enhanced passive honeypot with rate limiting & better logging ---
# 
#!/usr/bin/env python3
# 
# ============================================================================
#             T H I N K   B E V O R E   Y O U   T Y P E !
# ============================================================================
# NOTE ! Security is not eliminating it, 

import socket
import threading
import datetime
import hashlib
import json
import subprocess
import os
import time
import signal
import sys
import traceback
import platform
from collections import defaultdict
from pathlib import Path

# ============================================================================
# KONFIGURATION
# ============================================================================
SERVICE_PORT = 2222
LOG_DIR = "/var/log/honeypot"  # Nicht /tmp - das wird gecleart
LOG_MAX_SIZE_MB = 100  # Pro Log-File
ALERT_WEBHOOK = None  # z.B. "https://example.com/notify"
AUTO_BLOCK = False  # Nur mit WHITELIST aktivieren!
WHITELIST_IPS = ["127.0.0.1", "192.168.1.100"]  # Deine eigenen IPs

# Payload Detection (Optional)
PAYLOAD_FILE = None  # z.B. "/opt/honeypot/payloads.txt" oder URL
PAYLOAD_CHECK_ENABLED = False  # True um Payload-Detection zu aktivieren

# Rate Limiting
RATE_LIMIT_WINDOW = 60  # Sekunden
RATE_LIMIT_MAX_CONN = 15  # Max Connections pro IP in Window

# Response Payloads für verschiedene Services
BANNERS = {
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    "ftp": b"220 FTP Server ready\r\n",
    "http": b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
}
RESPONSE_PAYLOAD = BANNERS["ssh"]

# ============================================================================
# GLOBALS
# ============================================================================
conn_tracker = defaultdict(list)
blocked_ips = set()
shutdown_event = threading.Event()
known_payloads = set()  # Set für schnellere Lookups

# ============================================================================
# PAYLOAD DETECTION
# ============================================================================
def load_payloads_from_file(file_path: str) -> set:
    """Lädt Payloads aus lokaler Datei"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            payloads = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        print(f"[+] Loaded {len(payloads)} payloads from {file_path}")
        return payloads
    except Exception as e:
        print(f"[!] Failed to load payloads from {file_path}: {e}")
        return set()

def load_payloads_from_url(url: str) -> set:
    """Lädt Payloads von URL (z.B. GitHub raw)"""
    try:
        import urllib.request
        response = urllib.request.urlopen(url, timeout=10)
        data = response.read().decode('utf-8')
        payloads = {line.strip() for line in data.split('\n') if line.strip() and not line.startswith('#')}
        print(f"[+] Loaded {len(payloads)} payloads from {url}")
        return payloads
    except Exception as e:
        print(f"[!] Failed to load payloads from {url}: {e}")
        return set()

def check_for_known_payloads(data: str) -> dict:
    """Prüft ob bekannte Exploit-Payloads im Input enthalten sind"""
    if not PAYLOAD_CHECK_ENABLED or not known_payloads:
        return {"threat_detected": False}
    
    matches = [p for p in known_payloads if p.lower() in data.lower()]
    
    if matches:
        return {
            "threat_detected": True,
            "matched_payloads": matches[:5],  # Nur erste 5 loggen (Privacy)
            "match_count": len(matches),
            "threat_level": "high" if len(matches) > 3 else "medium"
        }
    
    return {"threat_detected": False}

# ============================================================================
# LOGGING
# ============================================================================
def setup_logging():
    """Erstellt Log-Verzeichnis mit richtigen Permissions"""
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True, mode=0o750)

def get_log_path():
    """Generiert Log-Pfad mit Datums-Rotation"""
    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, f"honeypot_{date_str}.jsonl")

def rotate_logs_if_needed(log_path):
    """Prüft Log-Größe und rotiert bei Bedarf"""
    try:
        if os.path.exists(log_path):
            size_mb = os.path.getsize(log_path) / (1024 * 1024)
            if size_mb > LOG_MAX_SIZE_MB:
                timestamp = datetime.datetime.utcnow().strftime("%H%M%S")
                rotated = f"{log_path}.{timestamp}"
                os.rename(log_path, rotated)
                print(f"[i] Log rotated: {rotated}")
    except Exception as e:
        print(f"[!] Log rotation failed: {e}")

def log_event(event: dict):
    """Schreibt Event als JSONL (eine Zeile pro Event)"""
    try:
        log_path = get_log_path()
        rotate_logs_if_needed(log_path)
        
        with open(log_path, "a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
            f.flush()  # Sofort schreiben
    except Exception as e:
        print(f"[!] Logging failed: {e}")
        traceback.print_exc()

# ============================================================================
# ALERTING
# ============================================================================
def send_alert(event: dict):
    """Sendet Alert via Webhook (non-blocking)"""
    if not ALERT_WEBHOOK:
        return
    
    def _send():
        try:
            import urllib.request
            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                ALERT_WEBHOOK,
                data=data,
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            log_event({
                "type": "alert_failed",
                "time": datetime.datetime.utcnow().isoformat(),
                "error": str(e)
            })
    
    threading.Thread(target=_send, daemon=True).start()

# ============================================================================
# RATE LIMITING
# ============================================================================
def rate_limit_check(ip: str) -> bool:
    """Prüft ob IP zu viele Connections macht"""
    now = time.time()
    
    # Cleanup alte Einträge
    conn_tracker[ip] = [t for t in conn_tracker[ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(conn_tracker[ip]) >= RATE_LIMIT_MAX_CONN:
        return False
    
    conn_tracker[ip].append(now)
    return True

# ============================================================================
# BLOCKING
# ============================================================================
def is_whitelisted(ip: str) -> bool:
    """Prüft ob IP auf Whitelist steht"""
    return ip in WHITELIST_IPS

def maybe_block(ip: str):
    """Blockt IP via iptables (nur wenn AUTO_BLOCK=True)"""
    if not AUTO_BLOCK or is_whitelisted(ip) or ip in blocked_ips:
        return
    
    try:
        # Check ob iptables verfügbar ist
        subprocess.run(["which", "iptables"], check=True, capture_output=True)
        
        cmd = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True, timeout=5)
        
        blocked_ips.add(ip)
        log_event({
            "type": "ip_blocked",
            "ip": ip,
            "time": datetime.datetime.utcnow().isoformat()
        })
        print(f"[!] BLOCKED: {ip}")
    except subprocess.CalledProcessError:
        log_event({
            "type": "block_failed",
            "ip": ip,
            "error": "iptables not available or permission denied",
            "time": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        log_event({
            "type": "block_failed",
            "ip": ip,
            "error": str(e),
            "time": datetime.datetime.utcnow().isoformat()
        })

# ============================================================================
# CONNECTION HANDLING
# ============================================================================
def parse_ssh_banner(data: bytes) -> dict:
    """Extrahiert Infos aus SSH Client-Banner"""
    try:
        banner = data.decode(errors="ignore").strip()
        parts = banner.split("-")
        if len(parts) >= 3 and parts[0] == "SSH":
            return {
                "protocol": parts[1],
                "software": "-".join(parts[2:]),
                "raw": banner
            }
    except:
        pass
    return {"raw": data.decode(errors="ignore")[:200]}

def connection_handler(conn, addr):
    """Handled eine eingehende Connection"""
    ip, port = addr[0], addr[1]
    ts = datetime.datetime.utcnow().isoformat()
    
    try:
        conn.settimeout(15.0)  # Längerer Timeout für langsame Scanner
        
        # Rate Limiting Check
        if not rate_limit_check(ip):
            log_event({
                "type": "rate_limited",
                "src_ip": ip,
                "src_port": port,
                "time": ts
            })
            maybe_block(ip)
            return
        
        # Daten empfangen
        try:
            data = conn.recv(4096)  # Mehr Daten für komplexere Payloads
        except socket.timeout:
            data = b""
        
        # Banner analysieren
        banner_info = parse_ssh_banner(data) if data else {}
        banner_str = banner_info.get("raw", "")
        
        # Payload Detection (falls aktiviert)
        threat_info = check_for_known_payloads(banner_str)
        
        # Fingerprint generieren
        fingerprint = hashlib.sha256(
            f"{ip}:{banner_str}".encode()
        ).hexdigest()[:16]
        
        # Event bauen
        event = {
            "type": "connection",
            "time": ts,
            "src_ip": ip,
            "src_port": port,
            "banner": banner_info,
            "fingerprint": fingerprint,
            "listener_port": SERVICE_PORT,
            "server_hostname": platform.node(),
            "data_length": len(data)
        }
        
        # Threat-Info hinzufügen (falls Detection aktiviert)
        if threat_info["threat_detected"]:
            event["threat_analysis"] = threat_info
        
        log_event(event)
        
        # Alert senden bei Threats oder verdächtigen Patterns
        if threat_info["threat_detected"] or len(data) > 0:
            send_alert(event)
        
        # Fake Response senden
        try:
            conn.sendall(RESPONSE_PAYLOAD)
            time.sleep(0.5)  # Simuliert "Verarbeitung"
        except Exception:
            pass
        
        # Optional: Bei mehreren Connections blocken
        if len(conn_tracker[ip]) > RATE_LIMIT_MAX_CONN * 0.7:  # 70% Threshold
            maybe_block(ip)
    
    except Exception as e:
        log_event({
            "type": "handler_error",
            "src_ip": ip,
            "error": str(e),
            "traceback": traceback.format_exc(),
            "time": ts
        })
    finally:
        try:
            conn.close()
        except:
            pass

# ============================================================================
# LISTENER
# ============================================================================
def listener():
    """Haupt-Listener Thread"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        s.bind(("0.0.0.0", SERVICE_PORT))
        s.listen(50)
        s.settimeout(1.0)  # Timeout für graceful shutdown
        
        print(f"[+] Honeypot listening on 0.0.0.0:{SERVICE_PORT}")
        print(f"[+] Logging to: {LOG_DIR}")
        print(f"[+] AUTO_BLOCK: {AUTO_BLOCK}")
        if AUTO_BLOCK:
            print(f"[+] Whitelisted IPs: {', '.join(WHITELIST_IPS)}")
        
        log_event({
            "type": "startup",
            "time": datetime.datetime.utcnow().isoformat(),
            "port": SERVICE_PORT,
            "auto_block": AUTO_BLOCK
        })
        
        while not shutdown_event.is_set():
            try:
                conn, addr = s.accept()
                t = threading.Thread(
                    target=connection_handler,
                    args=(conn, addr),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue  # Normal bei timeout, loop weiter
            except Exception as e:
                if not shutdown_event.is_set():
                    print(f"[!] Accept error: {e}")
    
    except Exception as e:
        print(f"[!] Listener failed: {e}")
        traceback.print_exc()
    finally:
        s.close()

# ============================================================================
# SIGNAL HANDLING
# ============================================================================
def signal_handler(sig, frame):
    """Graceful Shutdown bei SIGINT/SIGTERM"""
    print("\n[!] Shutting down honeypot...")
    log_event({
        "type": "shutdown",
        "time": datetime.datetime.utcnow().isoformat(),
        "signal": sig
    })
    shutdown_event.set()
    time.sleep(1)
    sys.exit(0)

# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    # Setup
    setup_logging()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Payload-Liste laden (falls aktiviert)
    if PAYLOAD_CHECK_ENABLED and PAYLOAD_FILE:
        print(f"[+] Loading payload list...")
        if PAYLOAD_FILE.startswith('http://') or PAYLOAD_FILE.startswith('https://'):
            known_payloads.update(load_payloads_from_url(PAYLOAD_FILE))
        else:
            known_payloads.update(load_payloads_from_file(PAYLOAD_FILE))
        
        if not known_payloads:
            print("[!] WARNING: Payload detection enabled but no payloads loaded!")
    
    # Warnungen ausgeben
    if AUTO_BLOCK and not WHITELIST_IPS:
        print("[!] WARNING: AUTO_BLOCK=True but no WHITELIST_IPS set!")
        print("[!] You might lock yourself out!")
        sys.exit(1)
    
    if os.geteuid() != 0 and SERVICE_PORT < 1024:
        print(f"[!] ERROR: Port {SERVICE_PORT} requires root privileges")
        print(f"[!] Run with sudo or use port >= 1024")
        sys.exit(1)
    
    # Start listener
    try:
        listener()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
