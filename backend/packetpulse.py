"""
scanner.py — Network scanning engine.

This is the core scanning logic extracted from packetpulse.py.
It has no knowledge of HTTP, auth, or the database — it just
scans and returns results. Routes call into this module.

Public API:
    get_network_details() -> dict
    run_scan(subnet, start, end, ports) -> list[dict]
"""

import socket
import platform
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
#  PORT MAP  — port: (label, category)
# ─────────────────────────────────────────────────────────────
PORT_MAP = {
    # Remote Access
    22:    ("SSH",           "remote"),
    23:    ("Telnet",        "remote"),
    3389:  ("RDP",           "remote"),
    5900:  ("VNC",           "remote"),
    5901:  ("VNC-1",         "remote"),
    # Web
    80:    ("HTTP",          "web"),
    443:   ("HTTPS",         "web"),
    8080:  ("HTTP-ALT",      "web"),
    8443:  ("HTTPS-ALT",     "web"),
    8888:  ("HTTP-DEV",      "web"),
    3000:  ("Node/React",    "web"),
    4000:  ("Dev Server",    "web"),
    # File Transfer
    21:    ("FTP",           "file"),
    69:    ("TFTP",          "file"),
    139:   ("NetBIOS",       "file"),
    445:   ("SMB",           "file"),
    2049:  ("NFS",           "file"),
    # Database
    1433:  ("MSSQL",         "database"),
    1521:  ("Oracle",        "database"),
    3306:  ("MySQL",         "database"),
    5432:  ("PostgreSQL",    "database"),
    5984:  ("CouchDB",       "database"),
    6379:  ("Redis",         "database"),
    9200:  ("Elasticsearch", "database"),
    27017: ("MongoDB",       "database"),
    # Mail
    25:    ("SMTP",          "mail"),
    110:   ("POP3",          "mail"),
    143:   ("IMAP",          "mail"),
    465:   ("SMTPS",         "mail"),
    587:   ("SMTP-TLS",      "mail"),
    993:   ("IMAPS",         "mail"),
    995:   ("POP3S",         "mail"),
    # Infrastructure
    53:    ("DNS",           "infra"),
    67:    ("DHCP",          "infra"),
    123:   ("NTP",           "infra"),
    161:   ("SNMP",          "infra"),
    389:   ("LDAP",          "infra"),
    636:   ("LDAPS",         "infra"),
    # DevOps
    2375:  ("Docker",        "devops"),
    2376:  ("Docker-TLS",    "devops"),
    6443:  ("Kubernetes",    "devops"),
    9090:  ("Prometheus",    "devops"),
    9100:  ("Node Exporter", "devops"),
    # Proxies / Tunnels
    1080:  ("SOCKS5",        "proxy"),
    3128:  ("Squid",         "proxy"),
    8118:  ("Privoxy",       "proxy"),
    1194:  ("OpenVPN",       "proxy"),
    # Dangerous / Suspicious
    4444:  ("Metasploit",    "danger"),
    5555:  ("ADB",           "danger"),
    7777:  ("Backdoor?",     "danger"),
    31337: ("Elite/Back",    "danger"),
}

# ─────────────────────────────────────────────────────────────
#  TUNING CONSTANTS
# ─────────────────────────────────────────────────────────────
TCP_TIMEOUT    = 0.25   # seconds per port probe
BANNER_TIMEOUT = 0.5    # seconds for banner grab
MAX_WORKERS    = 150    # threads for port scanning phase
PING_WORKERS   = 100    # threads for host discovery phase
PROBE_PORTS    = (80, 443, 22, 445, 3389, 8080, 23, 21)  # fast discovery probes


# ─────────────────────────────────────────────────────────────
#  NETWORK DETAILS
# ─────────────────────────────────────────────────────────────
def get_network_details() -> dict:
    """
    Detect the server's local IP and derive the subnet prefix.
    Returns a dict safe to send directly to the frontend.
    """
    import urllib.request
    details = {
        "local_ip":      "Unavailable",
        "public_ip":     "Unavailable",
        "subnet_prefix": "192.168.1",
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            details["local_ip"]      = s.getsockname()[0]
            details["subnet_prefix"] = ".".join(details["local_ip"].split(".")[:-1])
        req = urllib.request.Request("https://api.ipify.org?format=json")
        with urllib.request.urlopen(req, timeout=3) as resp:
            import json
            details["public_ip"] = json.loads(resp.read())["ip"]
    except Exception as e:
        log.debug("get_network_details partial failure: %s", e)
    return details


# ─────────────────────────────────────────────────────────────
#  PHASE 1 — HOST DISCOVERY
# ─────────────────────────────────────────────────────────────
def _is_host_up(ip: str) -> bool:
    """
    TCP knock on common ports first (fast, no root needed).
    Falls back to ICMP ping if all TCP probes fail.
    """
    for port in PROBE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            pass

    # ICMP fallback — may require elevated privileges on some systems
    try:
        param = ["-n", "1", f"-w{300}"] if platform.system().lower() == "windows" \
                else ["-c", "1", "-W", "1"]
        return subprocess.call(
            ["ping"] + param + [ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        ) == 0
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────
#  PHASE 2 — BANNER GRABBING
# ─────────────────────────────────────────────────────────────
def _grab_banner(ip: str, port: int) -> str:
    """
    Attempt to read a service banner from an open port.
    Returns the server version string if found, empty string otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))
            if port in (80, 8080, 8888, 3000, 4000):
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port in (443, 8443):
                return "TLS/SSL"
            raw    = s.recv(256)
            banner = raw.decode("utf-8", errors="replace").strip()
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:80]
            return banner.splitlines()[0][:80] if banner else ""
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────
#  PHASE 2 — PORT SCAN (called only on confirmed live hosts)
# ─────────────────────────────────────────────────────────────
def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""




# ─────────────────────────────────────────────────────────────
#  OS FINGERPRINTING
#  Uses TTL from ping + open port signatures + hostname hints
#  to make a best-effort OS guess. No raw sockets needed.
# ─────────────────────────────────────────────────────────────

# TTL thresholds — OS default TTLs degrade with each hop
# Windows: 128, Linux/Mac: 64, Cisco/network: 255
def _get_ttl(ip: str) -> int | None:
    """
    Extract TTL from ping response output.
    Returns integer TTL or None if unavailable.
    """
    try:
        is_win = platform.system().lower() == "windows"
        param  = ["-n", "1", f"-w500"] if is_win else ["-c", "1", "-W", "1"]
        result = subprocess.run(
            ["ping"] + param + [ip],
            capture_output=True, text=True, timeout=3
        )
        output = result.stdout + result.stderr
        # Windows: "TTL=128", Linux: "ttl=64"
        import re as _re
        match = _re.search(r"[Tt][Tt][Ll]=(\d+)", output)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return None


def _fingerprint_os(ip: str, open_ports: list[dict], hostname: str) -> dict:
    """
    Best-effort OS fingerprinting using:
    1. TTL value from ping
    2. Open port signatures
    3. Hostname pattern hints

    Returns:
        {
            "os_guess":      "Windows",
            "os_confidence": "medium",   # high / medium / low
            "os_detail":     "Windows 10/Server (TTL=128, RDP open)",
            "os_icon":       "windows"   # windows / linux / macos / network / unknown
        }
    """
    ttl        = _get_ttl(ip)
    port_nums  = {p["port"] for p in open_ports}
    hints      = []
    votes      = {"windows": 0, "linux": 0, "macos": 0, "network": 0}

    # ── TTL analysis ─────────────────────────────────────────
    if ttl is not None:
        if ttl >= 240:
            votes["network"] += 3
            hints.append(f"TTL={ttl} (network device)")
        elif ttl >= 110:
            votes["windows"] += 3
            hints.append(f"TTL={ttl} (Windows default 128)")
        elif ttl >= 55:
            votes["linux"] += 2
            votes["macos"] += 2
            hints.append(f"TTL={ttl} (Linux/macOS default 64)")
        else:
            hints.append(f"TTL={ttl} (many hops — inconclusive)")

    # ── Port signature analysis ───────────────────────────────
    # Windows-specific ports
    if 3389 in port_nums:   # RDP
        votes["windows"] += 3
        hints.append("RDP open")
    if 445 in port_nums:    # SMB
        votes["windows"] += 2
        hints.append("SMB open")
    if 139 in port_nums:    # NetBIOS
        votes["windows"] += 2
        hints.append("NetBIOS open")
    if 5985 in port_nums or 5986 in port_nums:  # WinRM
        votes["windows"] += 2
        hints.append("WinRM open")

    # Linux-specific ports
    if 22 in port_nums:     # SSH (common on Linux, rare on stock Windows)
        votes["linux"] += 1
        hints.append("SSH open")
    if 2049 in port_nums:   # NFS
        votes["linux"] += 2
        hints.append("NFS open")
    if 111 in port_nums:    # RPC
        votes["linux"] += 1

    # macOS-specific
    if 548 in port_nums:    # AFP (Apple Filing Protocol)
        votes["macos"] += 3
        hints.append("AFP open")
    if 5353 in port_nums:   # mDNS / Bonjour
        votes["macos"] += 2
        hints.append("mDNS/Bonjour")

    # Network device ports
    if 161 in port_nums:    # SNMP
        votes["network"] += 2
        hints.append("SNMP open")
    if 23 in port_nums:     # Telnet (common on routers)
        votes["network"] += 1
        hints.append("Telnet open")

    # Database servers (usually Linux)
    db_ports = {3306, 5432, 27017, 6379, 9200}
    if port_nums & db_ports:
        votes["linux"] += 1

    # ── Hostname pattern hints ────────────────────────────────
    hn = (hostname or "").lower()
    if any(w in hn for w in ["win", "desktop", "laptop", "workstation", "dc", "server"]):
        votes["windows"] += 1
    if any(w in hn for w in ["ubuntu", "debian", "centos", "fedora", "arch", "linux", "pi"]):
        votes["linux"] += 2
    if any(w in hn for w in ["macbook", "imac", "mac", "apple"]):
        votes["macos"] += 2
    if any(w in hn for w in ["router", "switch", "gateway", "cisco", "mikrotik", "ubnt"]):
        votes["network"] += 2

    # ── Determine winner ─────────────────────────────────────
    if not any(votes.values()):
        return {
            "os_guess":      "Unknown",
            "os_confidence": "low",
            "os_detail":     "Insufficient data to determine OS",
            "os_icon":       "unknown",
        }

    winner    = max(votes, key=votes.get)
    top_score = votes[winner]
    total     = sum(votes.values())

    # Confidence based on how dominant the winner is
    ratio = top_score / total if total else 0
    if ratio >= 0.7 and top_score >= 4:
        confidence = "high"
    elif ratio >= 0.5 or top_score >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    # Human-readable OS names and detail strings
    os_labels = {
        "windows": "Windows",
        "linux":   "Linux",
        "macos":   "macOS",
        "network": "Network Device",
    }
    os_details = {
        "windows": "Windows (likely 10/11 or Server)",
        "linux":   "Linux / Unix",
        "macos":   "macOS / Apple",
        "network": "Network Device (router/switch/appliance)",
    }

    detail = os_details[winner]
    if hints:
        detail += f" — {', '.join(hints[:3])}"

    return {
        "os_guess":      os_labels[winner],
        "os_confidence": confidence,
        "os_detail":     detail,
        "os_icon":       winner,
    }

def _scan_ports(ip: str, ports: list[int]) -> list[dict]:
    """
    Probe each port in the list. Returns only the open ones,
    each with label, category, and banner.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    label, category = PORT_MAP.get(port, ("Unknown", "infra"))
                    open_ports.append({
                        "port":     port,
                        "label":    label,
                        "category": category,
                        "banner":   _grab_banner(ip, port),
                    })
        except OSError:
            pass
    return open_ports


# ─────────────────────────────────────────────────────────────
#  PUBLIC: run_scan
# ─────────────────────────────────────────────────────────────
def run_scan(
    subnet: str,
    start:  int,
    end:    int,
    ports:  list[int] | None = None,
) -> list[dict]:
    """
    Execute a two-phase scan against subnet.start–end.

    Phase 1 — discovery sweep across the full range in parallel.
    Phase 2 — full port scan only on confirmed live hosts.

    Args:
        subnet: e.g. "192.168.1"
        start:  first host octet, 1–254
        end:    last host octet,  1–254
        ports:  list of port numbers to scan; None = all ports in PORT_MAP

    Returns:
        List of host dicts:
        [
          {
            "ip":       "192.168.1.1",
            "is_up":    True,
            "hostname": "router.local",
            "ports":    [{"port": 80, "label": "HTTP", ...}, ...]
          },
          ...
        ]
        Dead hosts are included with is_up=False and empty ports list
        so the frontend can show total hosts scanned vs alive.
    """
    if ports is None:
        ports = list(PORT_MAP.keys())

    all_ips  = [f"{subnet}.{i}" for i in range(start, end + 1)]
    ip_index = {ip: i for i, ip in enumerate(all_ips)}

    # Pre-fill all as dead; live results overwrite below
    results: list[dict] = [
        {"ip": ip, "is_up": False, "hostname": "", "ports": [], "os_guess": None, "os_confidence": None, "os_detail": None, "os_icon": None}
        for ip in all_ips
    ]

    # ── Phase 1: host discovery ──────────────────────────────
    log.info("Scan phase 1: discovering %d hosts on %s", len(all_ips), subnet)
    alive: list[str] = []
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futures = {ex.submit(_is_host_up, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    alive.append(ip)
            except Exception as e:
                log.debug("Discovery error for %s: %s", ip, e)

    log.info("Scan phase 1 complete: %d/%d hosts alive", len(alive), len(all_ips))

    if not alive:
        return results

    # ── Phase 2: port scan on live hosts only ────────────────
    log.info("Scan phase 2: port scanning %d live hosts", len(alive))
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(_scan_ports, ip, ports): ip for ip in alive}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                open_ports = future.result()
                hostname   = _resolve_hostname(ip)
                os_info    = _fingerprint_os(ip, open_ports, hostname)
                results[ip_index[ip]] = {
                    "ip":           ip,
                    "is_up":        True,
                    "hostname":     hostname,
                    "ports":        open_ports,
                    "os_guess":     os_info["os_guess"],
                    "os_confidence":os_info["os_confidence"],
                    "os_detail":    os_info["os_detail"],
                    "os_icon":      os_info["os_icon"],
                }
            except Exception as e:
                log.debug("Port scan error for %s: %s", ip, e)

    alive_count = sum(1 for r in results if r["is_up"])
    port_count  = sum(len(r["ports"]) for r in results)
    log.info("Scan phase 2 complete: %d open ports across %d hosts", port_count, alive_count)

    return results