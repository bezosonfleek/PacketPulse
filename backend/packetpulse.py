import socket, json, platform, subprocess, urllib.parse, urllib.request, os, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────────────────────
#  PORT MAP
# ─────────────────────────────────────────────────────────────
PORT_MAP = {
    22:    ("SSH",           "remote"),
    23:    ("Telnet",        "remote"),
    3389:  ("RDP",           "remote"),
    5900:  ("VNC",           "remote"),
    5901:  ("VNC-1",         "remote"),
    80:    ("HTTP",          "web"),
    443:   ("HTTPS",         "web"),
    8080:  ("HTTP-ALT",      "web"),
    8443:  ("HTTPS-ALT",     "web"),
    8888:  ("HTTP-DEV",      "web"),
    3000:  ("Node/React",    "web"),
    4000:  ("Dev Server",    "web"),
    21:    ("FTP",           "file"),
    69:    ("TFTP",          "file"),
    139:   ("NetBIOS",       "file"),
    445:   ("SMB",           "file"),
    2049:  ("NFS",           "file"),
    1433:  ("MSSQL",         "database"),
    1521:  ("Oracle",        "database"),
    3306:  ("MySQL",         "database"),
    5432:  ("PostgreSQL",    "database"),
    5984:  ("CouchDB",       "database"),
    6379:  ("Redis",         "database"),
    9200:  ("Elasticsearch", "database"),
    27017: ("MongoDB",       "database"),
    25:    ("SMTP",          "mail"),
    110:   ("POP3",          "mail"),
    143:   ("IMAP",          "mail"),
    465:   ("SMTPS",         "mail"),
    587:   ("SMTP-TLS",      "mail"),
    993:   ("IMAPS",         "mail"),
    995:   ("POP3S",         "mail"),
    53:    ("DNS",           "infra"),
    67:    ("DHCP",          "infra"),
    123:   ("NTP",           "infra"),
    161:   ("SNMP",          "infra"),
    389:   ("LDAP",          "infra"),
    636:   ("LDAPS",         "infra"),
    2375:  ("Docker",        "devops"),
    2376:  ("Docker-TLS",    "devops"),
    6443:  ("Kubernetes",    "devops"),
    9090:  ("Prometheus",    "devops"),
    9100:  ("Node Exporter", "devops"),
    1080:  ("SOCKS5",        "proxy"),
    3128:  ("Squid",         "proxy"),
    8118:  ("Privoxy",       "proxy"),
    1194:  ("OpenVPN",       "proxy"),
    4444:  ("Metasploit",    "danger"),
    5555:  ("ADB",           "danger"),
    7777:  ("Backdoor?",     "danger"),
    31337: ("Elite/Back",    "danger"),
}

TCP_TIMEOUT    = 0.25
BANNER_TIMEOUT = 0.5
MAX_WORKERS    = 150
PING_WORKERS   = 100
PROBE_PORTS    = (80, 443, 22, 445, 3389, 8080, 23, 21)

# ─────────────────────────────────────────────────────────────
#  SCANNING ENGINE
# ─────────────────────────────────────────────────────────────
def get_network_details():
    details = {"local_ip": "Detecting...", "public_ip": "Detecting...", "subnet_prefix": "192.168.1"}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            details["local_ip"] = s.getsockname()[0]
            details["subnet_prefix"] = ".".join(details["local_ip"].split('.')[:-1])
        with urllib.request.urlopen(urllib.request.Request('https://api.ipify.org?format=json'), timeout=3) as r:
            details["public_ip"] = json.loads(r.read())['ip']
    except: pass
    return details

def is_host_up(ip):
    for port in PROBE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except: pass
    try:
        param = ['-n','1',f'-w{300}'] if platform.system().lower()=='windows' else ['-c','1','-W','1']
        return subprocess.call(['ping']+param+[ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2) == 0
    except: return False

def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))
            if port in (80, 8080, 8888, 3000, 4000):
                s.sendall(b"GET / HTTP/1.0\r\nHost: "+ip.encode()+b"\r\n\r\n")
            elif port in (443, 8443): return "TLS/SSL"
            raw = s.recv(256)
            banner = raw.decode("utf-8", errors="replace").strip()
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":",1)[1].strip()[:55]
            return banner.splitlines()[0][:55] if banner else ""
    except: return ""

def resolve_hostname(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return ""

def scan_ports(ip, ports):
    results = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    label, cat = PORT_MAP.get(port, ("Unknown", "infra"))
                    results.append({"port": port, "label": label, "category": cat, "banner": grab_banner(ip, port)})
        except: pass
    return results

def run_scan(subnet, start, end, ports):
    all_ips  = [f"{subnet}.{i}" for i in range(start, end+1)]
    ip_index = {ip: i for i, ip in enumerate(all_ips)}
    results  = [{"ip": ip, "is_up": False, "hostname": "", "ports": []} for ip in all_ips]

    alive = []
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futs = {ex.submit(is_host_up, ip): ip for ip in all_ips}
        for f in as_completed(futs):
            ip = futs[f]
            try:
                if f.result(): alive.append(ip)
            except: pass

    if alive:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(scan_ports, ip, ports): ip for ip in alive}
            for f in as_completed(futs):
                ip = futs[f]
                try:
                    results[ip_index[ip]] = {"ip": ip, "is_up": True, "hostname": resolve_hostname(ip), "ports": f.result()}
                except: pass
    return results

# ─────────────────────────────────────────────────────────────
#  HTML
# ─────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>PacketPulse &mdash; Network Scanner</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="layout">

<!-- ═══════ SIDEBAR ═══════ -->
<aside class="sidebar" id="sidebar">

  <!-- Collapse toggle — always visible even when collapsed -->
  <button class="collapse-btn" id="collapse-btn" onclick="toggleSidebar()" title="Toggle sidebar">
    <span class="cb-label">Collapse</span>
    <span class="cb-icon">&#8249;</span>
  </button>

  <!-- All sidebar content hidden when collapsed -->
  <div class="sidebar-content" id="sidebar-content">
    <div class="sidebar-top">
      <div class="logo">Packet<em>Pulse</em></div>
      <div class="logo-sub">Network Scanner</div>
      <div class="sidebar-status" id="status-pill">
        <div class="s-dot online" id="s-dot"></div>
        <span class="s-label" id="s-label">Online</span>
        <span class="s-time" id="s-time"></span>
      </div>
    </div>

    <div class="sidebar-section">
      <div class="s-section-title">Network Info</div>
      <div class="net-item">
        <div class="net-label">Internal IP</div>
        <div class="net-val accent" id="lip">Detecting&hellip;</div>
      </div>
      <div class="net-item">
        <div class="net-label">Public IP</div>
        <div class="net-val" id="pip">Detecting&hellip;</div>
      </div>
    </div>

    <div class="sidebar-section">
      <div class="s-section-title">Last Scan</div>
      <div class="stat-row">
        <div class="stat-block">
          <div class="stat-num green" id="alive-count">&mdash;</div>
          <div class="stat-lbl">Hosts Alive</div>
        </div>
        <div class="stat-block">
          <div class="stat-num red" id="port-count">&mdash;</div>
          <div class="stat-lbl">Open Ports</div>
        </div>
      </div>
    </div>

    <div class="sidebar-section">
      <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">
        <span id="theme-label">Switch to Dark Mode</span>
        <span class="icon" id="theme-icon">&#9790;</span>
      </button>
    </div>

    <div class="sidebar-bottom">
      PacketPulse &bull; Pure Python &bull; No frameworks
    </div>
  </div><!-- /sidebar-content -->
</aside>

<!-- ═══════ RESIZE HANDLE ═══════ -->
<div class="resize-handle" id="resize-handle" title="Drag to resize sidebar"></div>

<!-- ═══════ MAIN ═══════ -->
<main class="main">

  <div class="page-header">
    <div class="page-title">Network Scan</div>
    <div class="page-sub">Discover live hosts and open services on your network</div>
  </div>

  <!-- Scan config -->
  <div class="card scan-card">
    <div class="card-header">
      <span class="card-title">Scan Configuration</span>
    </div>
    <div class="card-body">
      <div class="input-row">
        <div class="field grow">
          <label for="subnet">Subnet Prefix</label>
          <input type="text" id="subnet" placeholder="e.g. 192.168.1" autocomplete="off" spellcheck="false">
        </div>
        <div class="field sm">
          <label for="range-start">From</label>
          <input type="number" id="range-start" value="1" min="1" max="254">
        </div>
        <div class="field sm">
          <label for="range-end">To</label>
          <input type="number" id="range-end" value="254" min="1" max="254">
        </div>
        <div class="field">
          <label>&nbsp;</label>
          <button class="btn-scan" id="scan-btn" onclick="runScan()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
            Run Scan
          </button>
        </div>
      </div>
    </div>
    <div class="filter-row">
      <span class="filter-label">Filter:</span>
      <div class="cat-chip active" data-cat="remote"><div class="chip-dot"></div>Remote</div>
      <div class="cat-chip active" data-cat="web"><div class="chip-dot"></div>Web</div>
      <div class="cat-chip active" data-cat="file"><div class="chip-dot"></div>File Transfer</div>
      <div class="cat-chip active" data-cat="database"><div class="chip-dot"></div>Database</div>
      <div class="cat-chip active" data-cat="mail"><div class="chip-dot"></div>Mail</div>
      <div class="cat-chip active" data-cat="infra"><div class="chip-dot"></div>Infrastructure</div>
      <div class="cat-chip active" data-cat="devops"><div class="chip-dot"></div>DevOps</div>
      <div class="cat-chip active" data-cat="proxy"><div class="chip-dot"></div>Proxy/VPN</div>
      <div class="cat-chip active" data-cat="danger"><div class="chip-dot"></div>&#9888; Danger</div>
    </div>
  </div>

  <!-- Progress card — always in DOM, shown during scan -->
  <div class="card progress-card hidden" id="progress-card">
    <div class="progress-phases">
      <div class="phase-step" id="phase-1">
        <div class="phase-num">1</div>
        <div class="phase-info">
          <div class="phase-name">Host Discovery</div>
          <div class="phase-desc" id="phase-1-desc">Sweeping for live hosts&hellip;</div>
        </div>
      </div>
      <div class="phase-step" id="phase-2">
        <div class="phase-num">2</div>
        <div class="phase-info">
          <div class="phase-name">Port Scanning</div>
          <div class="phase-desc" id="phase-2-desc">Waiting&hellip;</div>
        </div>
      </div>
      <div class="phase-step" id="phase-3">
        <div class="phase-num">3</div>
        <div class="phase-info">
          <div class="phase-name">Complete</div>
          <div class="phase-desc" id="phase-3-desc">Results ready</div>
        </div>
      </div>
    </div>
    <div class="progress-bar-wrap">
      <div class="progress-track">
        <div class="progress-fill" id="progress-fill"></div>
      </div>
      <div class="progress-foot">
        <span class="progress-msg" id="progress-msg">Initialising scan&hellip;</span>
        <span class="progress-pct" id="progress-pct">0%</span>
      </div>
    </div>
  </div>

  <!-- Export banner — shown after scan -->
  <div class="export-banner hidden" id="export-banner">
    <div class="export-icon">&#8659;</div>
    <div class="export-text">
      <div class="export-title">Download Scan Results</div>
      <div class="export-sub" id="export-sub">Choose a format to save your results</div>
    </div>
    <div class="export-btns">
      <button class="btn-dl csv" onclick="exportCSV()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
        Download CSV
      </button>
      <button class="btn-dl json" onclick="exportJSON()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
        Download JSON
      </button>
    </div>
  </div>

  <!-- Results -->
  <div class="results-hdr">
    <div class="results-title">Discovered Hosts</div>
    <div class="results-meta" id="results-meta"></div>
  </div>

  <div id="results">
    <div class="empty-state">
      <div class="empty-icon">&#128225;</div>
      <div class="empty-title">No scan run yet</div>
      <div class="empty-sub">Configure your target above and click Run Scan to begin.</div>
    </div>
  </div>

</main>
</div><!-- /layout -->

<script src="/app.js"></script>
</body>
</html>"""

# ─────────────────────────────────────────────────────────────
#  SERVER
# ─────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
STATIC_FILES = {
    "/style.css": ("style.css", "text/css"),
    "/app.js":    ("app.js",    "application/javascript"),
}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass

    def send_ok(self, content, ct="text/html; charset=utf-8"):
        b = content if isinstance(content, bytes) else content.encode()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        url  = urllib.parse.urlparse(self.path)
        path = url.path.lower()

        if path in STATIC_FILES:
            fn, mime = STATIC_FILES[path]
            try:
                with open(os.path.join(BASE_DIR, fn), "rb") as f:
                    self.send_ok(f.read(), mime)
            except FileNotFoundError:
                self.send_error(404, f"{fn} not found")
            return

        if path in ("/", "/pulse"):
            self.send_ok(HTML); return

        if path == "/api/init":
            self.send_ok(json.dumps(get_network_details()), "application/json"); return

        if path == "/api/scan":
            q      = urllib.parse.parse_qs(url.query)
            subnet = q.get("target", ["192.168.1"])[0]
            start  = max(int(q.get("start", ["1"])[0]),   1)
            end    = min(int(q.get("end",   ["254"])[0]), 254)
            pp     = q.get("ports", [""])[0]
            ports  = [int(p) for p in pp.split(",") if p.isdigit()] if pp else list(PORT_MAP.keys())

            t0      = time.time()
            results = run_scan(subnet, start, end, ports)
            elapsed = round(time.time() - t0, 1)
            alive   = sum(1 for r in results if r["is_up"])
            print(f"  Scan: {end-start+1} hosts in {elapsed}s — {alive} alive")

            self.send_ok(json.dumps(results), "application/json"); return

        self.send_error(404, "Not Found")

if __name__ == "__main__":
    port = 8000
    print(f"\n  PacketPulse  |  http://localhost:{port}")
    print(f"  Ports: {len(PORT_MAP)}  |  Workers: {MAX_WORKERS} scan / {PING_WORKERS} discovery\n")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()