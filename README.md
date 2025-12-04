# Safe Honeypot

###### for Your AI and all other Servers : simple and clean trap

##### Lesson Philosophy:

> I show you a working system,
> 
> …but only pros can extend it with true red or black logic 😙



Safe Honeypot, a lightweight, production-ready SSH honeypot in Python for threat intelligence and attack detection on your own servers.

> "Learn this stuff… otherwise I’ll send a very angry worm after you. (Just kidding. Probably.)"

## Features

### 🔒 Security

* **Whitelist-based blocking** – Prevents accidental lockouts
* **Rate limiting** – Max 15 connections/minute per IP
* **Auto-block support** – Optional via iptables (securely disabled by default)
* **Graceful shutdown** – Clean exit via SIGINT/SIGTERM

### Logging & Monitoring

* **JSONL format** – One line per event, perfect for streaming/parsing
* **Automatic log rotation** – At 100MB (configurable)
* **Detailed event tracking** – Timestamps, IPs, banner, fingerprints
* **Webhook alerts** – Non-blocking threat notifications
* **Error tracking** – Full tracebacks for debugging

### Threat Detection

* **SSH banner parsing** – Extracts client protocol & software
* **Payload detection** – Optional: match against known exploit patterns
* **Fingerprinting** – SHA256-based attacker identification
* **Threat-level classification** – Automatic rating (medium/high)

### Performance

* **Multi-threading** – Parallel connection handling
* **15s timeout** – Detects slow scanners
* **4096 bytes buffer** – Captures more complex payloads
* **Set-based lookups** – O(1) payload matching

## Installation

```bash
# Clone repository
git clone <your-repo-url>
cd safe-honeypot

# Python 3.8+ required
python3 --version

# Optional: Virtual environment
python3 -m venv venv
source venv/bin/activate

# No dependencies for the base version!
# For extended features:
pip install geoip2  # Optional for GeoIP
```

## Configuration

All settings in `safe_honeypot.py` under `# CONFIGURATION`:

```python
# Basic settings
SERVICE_PORT = 2222              # Port (2222 = no sudo needed)
LOG_DIR = "/var/log/honeypot"    # Log directory
LOG_MAX_SIZE_MB = 100            # Rotation threshold

# Security
AUTO_BLOCK = False               # ONLY enable with whitelist!
WHITELIST_IPS = [                # Your own IPs
    "127.0.0.1",
    "192.168.1.100"
]

# Rate limiting
RATE_LIMIT_WINDOW = 60           # Time window in seconds
RATE_LIMIT_MAX_CONN = 15         # Max connections per IP

# Alerts (optional)
ALERT_WEBHOOK = None             # e.g. "https://hooks.slack.com/..."

# Payload detection (optional)
PAYLOAD_CHECK_ENABLED = False
PAYLOAD_FILE = None              # Local path or URL
```

### Enable Payload Detection

```python
# With local file
PAYLOAD_CHECK_ENABLED = True
PAYLOAD_FILE = "/opt/honeypot/payloads.txt"

# Or directly from GitHub
PAYLOAD_FILE = "https://raw.githubusercontent.com/user/repo/main/payloads.txt"
```

**Payload file format:**

```
# Comments with # are ignored
<script>alert(1)</script>
' OR '1'='1
../../../etc/passwd
<?php system($_GET['cmd']); ?>
```

## Usage

### Start

```bash
# With root (for ports < 1024)
sudo python3 safe_honeypot.py

# Without root (ports >= 1024, e.g. 2222)
python3 safe_honeypot.py

# In background with nohup
nohup python3 safe_honeypot.py > /dev/null 2>&1 &

# As systemd service (see below)
```

### Log Analysis

```bash
# Live monitoring
tail -f /var/log/honeypot/honeypot_$(date +%Y-%m-%d).jsonl

# Top attacker IPs
jq -r '.src_ip' /var/log/honeypot/*.jsonl | sort | uniq -c | sort -rn | head -10

# Detected threats
jq 'select(.threat_analysis.threat_detected == true)' /var/log/honeypot/*.jsonl

# Connections per hour
jq -r '.time[:13]' /var/log/honeypot/*.jsonl | uniq -c

# Unique fingerprints
jq -r '.fingerprint' /var/log/honeypot/*.jsonl | sort -u | wc -l

# Blocked IPs
jq -r 'select(.type == "ip_blocked") | .ip' /var/log/honeypot/*.jsonl
```

### Systemd Service

`/etc/systemd/system/honeypot.service`:

```ini
[Unit]
Description=Safe Honeypot Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/python3 /opt/honeypot/safe_honeypot.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable honeypot
sudo systemctl start honeypot
sudo systemctl status honeypot
```

## Event Structure

### Connection Event

```json
{
  "type": "connection",
  "time": "2024-12-02T10:30:45.123456",
  "src_ip": "1.2.3.4",
  "src_port": 54321,
  "banner": {
    "protocol": "2.0",
    "software": "OpenSSH_8.2p1",
    "raw": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
  },
  "fingerprint": "a3b5c7d9e1f2g4h6",
  "listener_port": 2222,
  "server_hostname": "web01",
  "data_length": 42,
  "threat_analysis": {
    "threat_detected": true,
    "matched_payloads": ["<script>", "' OR '1'='1"],
    "match_count": 2,
    "threat_level": "medium"
  }
}
```

### Rate Limited Event

```json
{
  "type": "rate_limited",
  "src_ip": "1.2.3.4",
  "src_port": 54322,
  "time": "2024-12-02T10:31:00.000000"
}
```

### Block Event

```json
{
  "type": "ip_blocked",
  "ip": "1.2.3.4",
  "time": "2024-12-02T10:31:05.000000"
}
```

## What Changed (vs. Base Version)

### JSONL instead of JSON

* One event = one line (better for streaming/parsing)
* Log rotation at 100MB (configurable)
* Date in filename: `honeypot_2024-12-02.jsonl`

### Rate Limiting

* Max 15 connections/minute per IP (adjustable)
* Automatic cleanup of old tracker entries
* At 70% threshold → auto-block (if enabled)

### Improved Logging

* Hostname included
* Data length for statistics
* Error handling with traceback
* Startup/shutdown events
* `flush()` for immediate writes

### Security

* Whitelist check before blocking
* Warning if AUTO_BLOCK without whitelist
* Port check (root needed for <1024)
* Graceful shutdown via SIGINT/SIGTERM

### Robustness

* 15s timeout (instead of 3s)
* 4096 bytes buffer (instead of 1024)
* Non-blocking webhook calls
* Exception handling everywhere

### SSH Banner Parsing

* Extracts protocol/software from client banner
* Fallback to raw data

### Payload Detection

* Optional exploit pattern integration
* Local file or remote URL support
* Case-insensitive matching
* Threat-level classification

## Extended Features

### GeoIP Integration

```bash
# Download MaxMind GeoLite2 DB
wget https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

# Extend code:
import geoip2.database

reader = geoip2.database.Reader('GeoLite2-City.mmdb')
response = reader.city(ip)
event["geo"] = {
    "country": response.country.iso_code,
    "city": response.city.name
}
```

### Fail2Ban Integration

`/etc/fail2ban/filter.d/honeypot.conf`:

```ini
[Definition]
failregex = "src_ip": "<HOST>"
ignoreregex =
```

`/etc/fail2ban/jail.local`:

```ini
[honeypot]
enabled = true
filter = honeypot
logpath = /var/log/honeypot/*.jsonl
maxretry = 3
bantime = 3600
```

### Telegram Alerts

```python
import requests

def send_telegram_alert(event):
    bot_token = "YOUR_BOT_TOKEN"
    chat_id = "YOUR_CHAT_ID"
    message = f"🚨 Threat detected!\nIP: {event['src_ip']}\nPayloads: {event['threat_analysis']['matched_payloads']}"
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    requests.post(url, json={"chat_id": chat_id, "text": message})
```

### Elasticsearch Export

```bash
# Bulk import via curl
cat /var/log/honeypot/*.jsonl | while read line; do
  curl -X POST "localhost:9200/honeypot/_doc" \
    -H 'Content-Type: application/json' \
    -d "$line"
done

# Or with Logstash/Filebeat
```

## Security Notes

⚠️ **IMPORTANT:**

1. **Never run on production servers** with critical services
2. **AUTO_BLOCK only with whitelist** (risk of locking yourself out)
3. **Separate network segment** recommended for honeypots
4. **Check logs regularly** – may contain sensitive data
5. **Use payload lists responsibly** – defensive purposes only

## Troubleshooting

### Port already in use

```bash
# Check port usage
sudo lsof -i :2222

# Set another port in config
SERVICE_PORT = 3333
```

### Permission Denied

```bash
# Ports < 1024 require root
sudo python3 safe_honeypot.py

# Or use port >= 1024
SERVICE_PORT = 2222
```

### Logs not written

```bash
# Check directory permissions
sudo mkdir -p /var/log/honeypot
sudo chown $USER:$USER /var/log/honeypot
sudo chmod 750 /var/log/honeypot
```

### iptables error with AUTO_BLOCK

```bash
# sudo rights for user
sudo visudo
# Add:
your_user ALL=(ALL) NOPASSWD: /sbin/iptables

# Or use fail2ban (recommended)
```

## Next Steps / Roadmap

* [ ] **GeoIP integration** – `pip install geoip2` + MaxMind DB
* [ ] **Multi-protocol support** – FTP, HTTP, Telnet emulation
* [ ] **Fail2Ban integration** – Instead of custom iptables calls
* [ ] **Telegram bot** – Realtime alerts
* [ ] **Elasticsearch export** – Long-term analytics
* [ ] **Docker container** – Easy deployment
* [ ] **Dashboard/UI** – Web interface for log analysis
* [ ] **Machine learning** – Anomaly detection

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push the branch (`git push origin feature/AmazingFeature`)
5. Open a pull request

## License

MIT License – see LICENSE file

## Credits

Developed for defensive security & threat intelligence.

**Note:** This tool is intended strictly for defensive use on your own systems.
Misuse for offensive actions against third parties is illegal.

## Support

If you have questions or issues:

* Open a GitHub issue
* Check logs using the `--debug` flag
* Community Discord (if available)

---

**Stay safe, stay informed! 🔒**
