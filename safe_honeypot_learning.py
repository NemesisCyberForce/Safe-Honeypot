# 
#  DISCLAIMER: Responsibility and Legality
# 
# You are entirely responsible for how you use this code. Understand the legal
# implications in your jurisdiction regarding network monitoring and automated blocking.
# Test this only on networks and servers you own or are authorized to monitor.
# 
# ---
# 
#  Learn how to create an basic honeypot for your Server Security
#!/usr/bin/env python3
"""
safe_honeypot.py — Passive Honeypot (Logging + Alerting)

LEARNING EDITION: Optimized basic version with detailed comments
This is educational code - understand each part before deploying!

Purpose: Log incoming connections, fingerprint attackers, optionally alert/block
Security: Passive only - never scans or attacks back
"""

import socket          # Network connections
import threading       # Handle multiple connections simultaneously
import datetime        # Timestamps for logs
import hashlib         # Create fingerprints of attackers
import json            # Structured logging format
import subprocess      # Execute system commands (iptables)
import os              # File system operations
from urllib import request  # Send webhook alerts

# ============================================================================
# CONFIGURATION - Adjust these values for your environment
# ============================================================================

# Network range (documentary only - we never actively scan!)
TARGET_RANGE = "192.168.1.0/24"

# Port to listen on (use >1024 to avoid needing root)
# Common choices: 2222 (fake SSH), 8080 (fake HTTP), 21 (fake FTP)
SERVICE_PORT = 2222

# Where to store log files (IMPORTANT: /tmp gets cleared on reboot!)
# Production: Use /var/log/honeypot instead
LOG_DIR = "/tmp/honeypot_logs"

# Optional: Webhook URL for real-time alerts (Slack, Discord, etc.)
# Example: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
ALERT_WEBHOOK = None

# DANGER: Only enable after setting up whitelist! (see production version)
# Without whitelist, you WILL lock yourself out eventually
AUTO_BLOCK = False

# Fake SSH banner to trick attackers into thinking this is real
# Mimics OpenSSH 7.9 on Debian - attackers see this and continue
RESPONSE_PAYLOAD = b"SSH-2.0-OpenSSH_7.9p1 Debian-10\r\n"

# Create log directory if it doesn't exist
os.makedirs(LOG_DIR, exist_ok=True)

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def log_event(event: dict):
    """
    Write event to JSONL file (JSON Lines - one event per line)
    
    Why JSONL instead of JSON?
    - Each line is valid JSON (easy to parse line-by-line)
    - Append-safe (no need to rewrite entire file)
    - Stream-friendly (tail -f works perfectly)
    
    File naming: YYYYMMDD.jsonl (automatic daily rotation)
    """
    # Generate filename with current date
    fname = datetime.datetime.utcnow().strftime("%Y%m%d") + ".jsonl"
    path = os.path.join(LOG_DIR, fname)
    
    # Append mode ('a') - doesn't overwrite existing data
    with open(path, "a") as f:
        # ensure_ascii=False allows unicode characters
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def send_alert(event: dict):
    """
    Send real-time alert via webhook (non-blocking)
    
    Use cases:
    - Slack/Discord notifications
    - Trigger other security tools
    - Update threat intelligence databases
    
    Note: This runs synchronously - for high traffic, use threading
    """
    if not ALERT_WEBHOOK:
        return  # Alerts disabled
    
    # Convert dict to JSON bytes
    data = json.dumps(event).encode("utf-8")
    req = request.Request(
        ALERT_WEBHOOK, 
        data=data, 
        headers={"Content-Type": "application/json"}
    )
    
    try:
        # 5 second timeout prevents hanging
        request.urlopen(req, timeout=5)
    except Exception as e:
        # If alert fails, log it (but don't create infinite loop!)
        event["alert_error"] = str(e)
        log_event({
            "note": "alert_failed",
            "time": datetime.datetime.utcnow().isoformat(),
            "error": str(e)
        })

# ============================================================================
# BLOCKING FUNCTIONS (Use with extreme caution!)
# ============================================================================

def maybe_block(ip: str):
    """
    Optionally block attacking IP via iptables
    
    WARNING: This is dangerous without proper safeguards!
    Production requirements:
    1. Whitelist of your own IPs (never block yourself)
    2. Rate limiting (don't block on single connection)
    3. Temporary blocks (auto-expire after X hours)
    4. fail2ban integration instead of direct iptables
    
    Current implementation: Disabled by default (AUTO_BLOCK=False)
    """
    if not AUTO_BLOCK:
        return  # Blocking disabled
    
    # SECURITY: Always check whitelist in production!
    # Example: if ip in WHITELIST_IPS: return
    
    # iptables command: Insert rule at position 1 to DROP packets from IP
    cmd = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
    
    try:
        subprocess.run(cmd, check=True)
        log_event({
            "action": "blocked",
            "ip": ip,
            "time": datetime.datetime.utcnow().isoformat()
        })
    except Exception as e:
        # Log failure (maybe sudo not configured, iptables missing, etc.)
        log_event({
            "action": "block_failed",
            "ip": ip,
            "error": str(e),
            "time": datetime.datetime.utcnow().isoformat()
        })

# ============================================================================
# CONNECTION HANDLING
# ============================================================================

def connection_handler(conn, addr):
    """
    Handle a single incoming connection (runs in separate thread)
    
    Flow:
    1. Extract IP and port from connection
    2. Try to receive data (with timeout)
    3. Create fingerprint from IP + banner
    4. Log everything
    5. Send fake response (make attacker think it's real)
    6. Optionally block the IP
    7. Close connection
    
    Threading: Each connection gets its own thread (daemon=True means
    it dies when main program exits, preventing zombie threads)
    """
    ip, port = addr[0], addr[1]
    ts = datetime.datetime.utcnow().isoformat()  # ISO 8601 timestamp
    
    try:
        # IMPROVEMENT NEEDED: 3 seconds is too short for slow scanners
        # Production: Use 10-15 seconds
        conn.settimeout(3.0)
        
        try:
            # IMPROVEMENT NEEDED: 1024 bytes may miss complex payloads
            # Production: Use 4096 bytes
            data = conn.recv(1024)
        except socket.timeout:
            # Timeout is normal - many scanners just connect and wait
            data = b""
        
        # Decode bytes to string, ignore invalid UTF-8 (binary data)
        banner = data.decode(errors="ignore")
        
        # Create unique fingerprint: SHA256(IP + banner)
        # Why? Same attacker = same fingerprint = track campaigns
        fingerprint = hashlib.sha256((ip + banner).encode()).hexdigest()
        
        # Build structured event for logging
        event = {
            "time": ts,
            "src_ip": ip,
            "src_port": port,
            "banner": banner,
            "fingerprint": fingerprint,
            "listener_port": SERVICE_PORT
        }
        
        # Log to file
        log_event(event)
        
        # Send real-time alert (if configured)
        send_alert(event)
        
        # Send fake response to deceive attacker
        # Makes them think this is a real SSH server
        try:
            conn.sendall(RESPONSE_PAYLOAD)
        except Exception:
            # Connection might be closed already - not critical
            pass
        
        # Optionally block this IP from further connections
        maybe_block(ip)
    
    finally:
        # ALWAYS close connection (even if exception occurred)
        # Prevents resource leaks and file descriptor exhaustion
        conn.close()

# ============================================================================
# MAIN LISTENER
# ============================================================================

def listener():
    """
    Main server loop - accepts incoming connections forever
    
    Socket options explained:
    - AF_INET: IPv4 (use AF_INET6 for IPv6)
    - SOCK_STREAM: TCP (use SOCK_DGRAM for UDP)
    - SO_REUSEADDR: Allow binding to port immediately after restart
                    (without this, "Address already in use" error for ~60s)
    
    Bind "0.0.0.0" means: Listen on ALL network interfaces
    - localhost (127.0.0.1)
    - LAN interface (192.168.x.x)
    - Public IP (if server has one)
    
    Listen backlog (50): How many pending connections to queue
    - Too low: Connections get refused during attack spikes
    - Too high: Resource waste
    - 50 is reasonable for honeypot
    """
    # Create TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Allow immediate port reuse (important for quick restarts)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Bind to all interfaces on specified port
    s.bind(("0.0.0.0", SERVICE_PORT))
    
    # Start listening (backlog = 50 pending connections)
    s.listen(50)
    
    print(f"[+] safe honeypot listening on 0.0.0.0:{SERVICE_PORT}")
    print(f"[+] Logs: {LOG_DIR}")
    print(f"[+] Press Ctrl+C to stop")
    
    # IMPROVEMENT NEEDED: No graceful shutdown
    # Production: Add signal handler for SIGINT/SIGTERM
    while True:
        # Block until connection arrives (accept() is blocking)
        conn, addr = s.accept()
        
        # Spawn new thread to handle connection
        # daemon=True: Thread dies when main program exits
        # Without threading: One slow connection blocks all others!
        t = threading.Thread(
            target=connection_handler,
            args=(conn, addr),
            daemon=True
        )
        t.start()

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    """
    Python convention: Only run if script is executed directly
    (not if imported as module)
    
    IMPROVEMENTS NEEDED FOR PRODUCTION:
    1. Rate limiting (prevent DDoS from filling logs/memory)
    2. Log rotation (prevent disk full)
    3. Graceful shutdown (save state, close sockets cleanly)
    4. Whitelist for AUTO_BLOCK (never lock yourself out)
    5. Better timeout handling (catch slow scanners)
    6. Payload detection (recognize known exploits)
    7. GeoIP integration (where do attacks come from?)
    8. systemd service file (auto-start on boot)
    
    This is a LEARNING version - understand it, then use production code!
    """
    try:
        listener()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        # IMPROVEMENT: Add proper cleanup here
        # - Close all open connections
        # - Flush log buffers
        # - Log shutdown event
