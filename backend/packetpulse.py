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


# ─────────────────────────────────────────────────────────────
#  CVE PORT MAP
#  Static mapping of port → known CVEs for that service.
#  Based on historically significant, widely-referenced CVEs.
#  Each entry: (cve_id, cvss_score, severity, description)
#  severity: critical / high / medium / low / info
# ─────────────────────────────────────────────────────────────
CVE_MAP: dict[int, list[dict]] = {
    # ── SSH (22) ─────────────────────────────────────────────
    22: [
        {"id": "CVE-2023-38408", "cvss": 9.8, "severity": "critical",
         "desc": "OpenSSH ssh-agent remote code execution via forwarded agent socket"},
        {"id": "CVE-2023-51385", "cvss": 9.8, "severity": "critical",
         "desc": "OpenSSH OS command injection via shell metacharacters in hostname"},
        {"id": "CVE-2016-0777",  "cvss": 6.5, "severity": "medium",
         "desc": "OpenSSH information disclosure via roaming feature (memory leak)"},
        {"id": "CVE-2018-15473", "cvss": 5.3, "severity": "medium",
         "desc": "OpenSSH username enumeration via timing difference in auth responses"},
    ],
    # ── Telnet (23) ──────────────────────────────────────────
    23: [
        {"id": "CVE-2011-4862",  "cvss": 10.0, "severity": "critical",
         "desc": "BSD telnetd remote code execution via encrypt_keyid buffer overflow"},
        {"id": "CVE-2020-10188", "cvss": 9.8,  "severity": "critical",
         "desc": "telnetd arbitrary RCE via environment variable injection (utility.c)"},
    ],
    # ── FTP (21) ─────────────────────────────────────────────
    21: [
        {"id": "CVE-2015-3306",  "cvss": 10.0, "severity": "critical",
         "desc": "ProFTPd mod_copy unauthenticated arbitrary file read/write via CPFR/CPTO"},
        {"id": "CVE-2011-2523",  "cvss": 10.0, "severity": "critical",
         "desc": "vsftpd 2.3.4 backdoor — connects to port 6200 on smiley-face username"},
        {"id": "CVE-2010-4221",  "cvss": 10.0, "severity": "critical",
         "desc": "ProFTPd SQL injection via TELNET_IAC escape sequences"},
    ],
    # ── HTTP (80) ────────────────────────────────────────────
    80: [
        {"id": "CVE-2021-41773", "cvss": 7.5, "severity": "high",
         "desc": "Apache 2.4.49 path traversal and RCE via mod_cgi (actively exploited)"},
        {"id": "CVE-2021-42013", "cvss": 9.8, "severity": "critical",
         "desc": "Apache 2.4.49-2.4.50 path traversal bypass — RCE without mod_cgi"},
        {"id": "CVE-2022-22965", "cvss": 9.8, "severity": "critical",
         "desc": "Spring4Shell — Spring MVC RCE via data binding on JDK 9+"},
        {"id": "CVE-2017-5638",  "cvss": 10.0, "severity": "critical",
         "desc": "Apache Struts2 RCE via Content-Type header (Equifax breach vector)"},
    ],
    # ── HTTPS (443) ──────────────────────────────────────────
    443: [
        {"id": "CVE-2014-0160",  "cvss": 7.5, "severity": "high",
         "desc": "Heartbleed — OpenSSL TLS heartbeat read overrun leaks server memory"},
        {"id": "CVE-2014-3566",  "cvss": 3.4, "severity": "low",
         "desc": "POODLE — SSLv3 CBC padding oracle allows MITM decryption"},
        {"id": "CVE-2016-2107",  "cvss": 5.9, "severity": "medium",
         "desc": "OpenSSL AES-NI CBC padding oracle — MITM plaintext recovery"},
        {"id": "CVE-2021-3449",  "cvss": 5.9, "severity": "medium",
         "desc": "OpenSSL NULL pointer deref in TLSv1.2 renegotiation — remote DoS"},
    ],
    # ── SMB (445) ────────────────────────────────────────────
    445: [
        {"id": "CVE-2017-0144",  "cvss": 8.1, "severity": "high",
         "desc": "EternalBlue — SMBv1 RCE used by WannaCry and NotPetya ransomware"},
        {"id": "CVE-2017-0145",  "cvss": 8.1, "severity": "high",
         "desc": "EternalRomance — SMBv1 RCE via transaction request out-of-bounds write"},
        {"id": "CVE-2020-0796",  "cvss": 10.0, "severity": "critical",
         "desc": "SMBGhost — SMBv3.1.1 compression RCE without authentication"},
        {"id": "CVE-2021-36942", "cvss": 7.5, "severity": "high",
         "desc": "PetitPotam — unauthenticated NTLM relay via MS-EFSRPC to NTLM relay"},
    ],
    # ── RDP (3389) ───────────────────────────────────────────
    3389: [
        {"id": "CVE-2019-0708",  "cvss": 9.8, "severity": "critical",
         "desc": "BlueKeep — pre-auth RDP RCE on Windows 7/Server 2008 (wormable)"},
        {"id": "CVE-2019-1181",  "cvss": 9.8, "severity": "critical",
         "desc": "DejaBlue — RDP pre-auth RCE on Windows 8/10/Server 2012-2019"},
        {"id": "CVE-2012-0002",  "cvss": 9.3, "severity": "critical",
         "desc": "MS12-020 — RDP pre-auth double-free DoS / potential RCE"},
    ],
    # ── VNC (5900/5901) ──────────────────────────────────────
    5900: [
        {"id": "CVE-2019-15694", "cvss": 9.8, "severity": "critical",
         "desc": "LibVNCServer heap overflow in HandleCursorShape — RCE"},
        {"id": "CVE-2019-15681", "cvss": 7.5, "severity": "high",
         "desc": "LibVNCServer memory leak exposes stack/heap contents to clients"},
    ],
    5901: [
        {"id": "CVE-2019-15694", "cvss": 9.8, "severity": "critical",
         "desc": "LibVNCServer heap overflow in HandleCursorShape — RCE"},
    ],
    # ── MySQL (3306) ─────────────────────────────────────────
    3306: [
        {"id": "CVE-2012-2122",  "cvss": 5.1, "severity": "medium",
         "desc": "MySQL auth bypass — repeated auth attempts succeed due to memcmp timing"},
        {"id": "CVE-2016-6662",  "cvss": 9.8, "severity": "critical",
         "desc": "MySQL RCE via malicious my.cnf injection through SQL FILE privilege"},
        {"id": "CVE-2021-27928", "cvss": 7.2, "severity": "high",
         "desc": "MariaDB/MySQL RCE via wsrep provider shared library path injection"},
    ],
    # ── PostgreSQL (5432) ────────────────────────────────────
    5432: [
        {"id": "CVE-2019-9193",  "cvss": 8.8, "severity": "high",
         "desc": "PostgreSQL COPY TO/FROM PROGRAM allows OS command execution (superuser)"},
        {"id": "CVE-2019-10164", "cvss": 8.8, "severity": "high",
         "desc": "PostgreSQL stack overflow in scram_verify_plain_password — potential RCE"},
    ],
    # ── Redis (6379) ─────────────────────────────────────────
    6379: [
        {"id": "CVE-2022-0543",  "cvss": 10.0, "severity": "critical",
         "desc": "Redis Lua sandbox escape allows arbitrary code execution on host"},
        {"id": "CVE-2021-32762", "cvss": 8.8, "severity": "high",
         "desc": "Redis integer overflow in COPY destination key processing — heap RCE"},
    ],
    # ── MongoDB (27017) ──────────────────────────────────────
    27017: [
        {"id": "CVE-2021-20328", "cvss": 6.8, "severity": "medium",
         "desc": "MongoDB no TLS certificate validation — server identity unverified"},
        {"id": "CVE-2015-7882",  "cvss": 7.5, "severity": "high",
         "desc": "MongoDB LDAP auth bypass allows unauthorized access with empty password"},
    ],
    # ── Elasticsearch (9200) ─────────────────────────────────
    9200: [
        {"id": "CVE-2021-22145", "cvss": 6.5, "severity": "medium",
         "desc": "Elasticsearch memory disclosure via pieced-together exception messages"},
        {"id": "CVE-2014-3120",  "cvss": 7.5, "severity": "high",
         "desc": "Elasticsearch dynamic script RCE via Groovy/MVEL script engine"},
        {"id": "CVE-2015-1427",  "cvss": 10.0, "severity": "critical",
         "desc": "Elasticsearch Groovy sandbox escape — unauthenticated RCE (Shellshock-class)"},
    ],
    # ── MSSQL (1433) ─────────────────────────────────────────
    1433: [
        {"id": "CVE-2020-0618",  "cvss": 8.8, "severity": "high",
         "desc": "SQL Server Reporting Services RCE via deserialization of report data"},
        {"id": "CVE-2019-1068",  "cvss": 8.8, "severity": "high",
         "desc": "SQL Server RCE via malformed OpenXML document in linked server query"},
    ],
    # ── SMTP (25) ────────────────────────────────────────────
    25: [
        {"id": "CVE-2020-7247",  "cvss": 9.8, "severity": "critical",
         "desc": "OpenSMTPD RCE via malformed sender address — pre-auth in default config"},
        {"id": "CVE-2019-15846", "cvss": 9.8, "severity": "critical",
         "desc": "Exim RCE via EHLO/HELO with string ending in backslash-null sequence"},
    ],
    # ── LDAP (389) ───────────────────────────────────────────
    389: [
        {"id": "CVE-2021-44228", "cvss": 10.0, "severity": "critical",
         "desc": "Log4Shell — JNDI LDAP lookup in log messages triggers RCE (Log4j 2.x)"},
        {"id": "CVE-2017-8563",  "cvss": 8.1, "severity": "high",
         "desc": "Windows LDAP elevation of privilege via NTLM pass-through auth relay"},
    ],
    # ── Docker (2375) ────────────────────────────────────────
    2375: [
        {"id": "CVE-2019-5736",  "cvss": 8.6, "severity": "high",
         "desc": "runc container escape — overwrite host runc binary via /proc/self/exe"},
        {"id": "CVE-2020-15257", "cvss": 5.2, "severity": "medium",
         "desc": "containerd UNIX socket privilege escalation via abstract namespace"},
    ],
    # ── Kubernetes (6443) ────────────────────────────────────
    6443: [
        {"id": "CVE-2018-1002105", "cvss": 9.8, "severity": "critical",
         "desc": "Kubernetes API server privilege escalation via backend connection upgrade"},
        {"id": "CVE-2019-11247",   "cvss": 8.1, "severity": "high",
         "desc": "Kubernetes API server allows access to cluster-scoped resources as namespace resources"},
    ],
    # ── HTTP-ALT (8080) ──────────────────────────────────────
    8080: [
        {"id": "CVE-2021-41773", "cvss": 7.5, "severity": "high",
         "desc": "Apache 2.4.49 path traversal and RCE — often runs on alt HTTP ports"},
        {"id": "CVE-2020-9484",  "cvss": 7.0, "severity": "high",
         "desc": "Apache Tomcat RCE via deserialization when PersistentManager is configured"},
    ],
    # ── SNMP (161) ───────────────────────────────────────────
    161: [
        {"id": "CVE-2017-6736",  "cvss": 9.8, "severity": "critical",
         "desc": "Cisco IOS SNMP RCE via crafted SNMP packet — buffer overflow in subsystem"},
        {"id": "CVE-2002-0013",  "cvss": 10.0, "severity": "critical",
         "desc": "SNMP v1 trap handling multiple buffer overflows — affects many vendors"},
    ],
    # ── NetBIOS (139) ────────────────────────────────────────
    139: [
        {"id": "CVE-2017-0143",  "cvss": 8.1, "severity": "high",
         "desc": "EternalBlue variant targeting NetBIOS/SMB — same WannaCry attack chain"},
        {"id": "CVE-2008-4250",  "cvss": 10.0, "severity": "critical",
         "desc": "MS08-067 — Windows Server Service RCE via crafted RPC request (Conficker)"},
    ],
    # ── NFS (2049) ───────────────────────────────────────────
    2049: [
        {"id": "CVE-2017-12136", "cvss": 7.8, "severity": "high",
         "desc": "Linux kernel NFS xdr_decode_string_inplace — denial of service"},
        {"id": "CVE-2019-3010",  "cvss": 8.8, "severity": "high",
         "desc": "Oracle Solaris NFS local privilege escalation via kernel module"},
    ],
    # ── Metasploit / Backdoor ports ──────────────────────────
    4444: [
        {"id": "INDICATOR-4444", "cvss": 10.0, "severity": "critical",
         "desc": "Default Metasploit payload listener port — active exploitation likely"},
    ],
    5555: [
        {"id": "INDICATOR-5555", "cvss": 9.0, "severity": "critical",
         "desc": "Android Debug Bridge (ADB) open — full device control without auth"},
    ],
    31337: [
        {"id": "INDICATOR-31337", "cvss": 10.0, "severity": "critical",
         "desc": "Elite/Back Orifice backdoor port — historic remote access trojan"},
    ],
}


def _lookup_cves(port: int) -> list[dict]:
    """Return CVE list for a given port, empty list if none known."""
    return CVE_MAP.get(port, [])


# ─────────────────────────────────────────────────────────────
#  MAC ADDRESS DETECTION
#  Reads the OS ARP cache after the host has been pinged/probed.
#  Works on the local subnet only (Layer 2). No extra privileges.
#  Windows: parses `arp -a`, Linux: reads /proc/net/arp
# ─────────────────────────────────────────────────────────────
def _get_mac(ip: str) -> tuple[str, str]:
    """
    Look up the MAC address for an IP from the OS ARP cache.
    Returns (mac_address, vendor_prefix) or ("", "").
    mac_address is formatted as XX:XX:XX:XX:XX:XX (upper).
    vendor_prefix is the OUI-based vendor name if known.
    """
    import re as _re
    mac = ""

    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True, text=True, timeout=3
            )
            # Windows arp output: "  192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic"
            match = _re.search(r"([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})", result.stdout, _re.IGNORECASE)
            if match:
                mac = match.group(1).replace("-", ":").upper()
        else:
            # Linux — /proc/net/arp is fastest, no subprocess needed
            try:
                with open("/proc/net/arp") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            candidate = parts[3]
                            if candidate != "00:00:00:00:00:00":
                                mac = candidate.upper()
                                break
            except Exception:
                pass
            # Fallback: arp -n
            if not mac:
                result = subprocess.run(
                    ["arp", "-n", ip],
                    capture_output=True, text=True, timeout=3
                )
                match = _re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", result.stdout, _re.IGNORECASE)
                if match:
                    mac = match.group(1).upper()
    except Exception:
        pass

    vendor = _oui_lookup(mac) if mac else ""
    return mac, vendor


# Compact OUI table — first 3 octets of MAC → vendor name
# Covers the most common enterprise/consumer vendors
_OUI_TABLE = {
    "00:50:56": "VMware",         "00:0C:29": "VMware",
    "00:1C:42": "Parallels",      "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",       "00:16:3E": "Xen",
    "B8:27:EB": "Raspberry Pi",   "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",   "28:CD:C1": "Raspberry Pi",
    "00:1A:11": "Google",         "F4:F5:E8": "Google",
    "3C:5A:B4": "Google",
    "00:17:F2": "Apple",          "00:1E:C2": "Apple",
    "00:23:DF": "Apple",          "04:54:53": "Apple",
    "08:70:45": "Apple",          "0C:74:C2": "Apple",
    "14:8F:C6": "Apple",          "28:6A:BA": "Apple",
    "3C:07:54": "Apple",          "8C:85:90": "Apple",
    "AC:DE:48": "Apple",          "F0:DB:F8": "Apple",
    "00:14:22": "Dell",           "00:1A:A0": "Dell",
    "00:21:70": "Dell",           "18:03:73": "Dell",
    "B0:83:FE": "Dell",           "F8:DB:88": "Dell",
    "00:1B:21": "Intel",          "00:1E:64": "Intel",
    "00:1F:3B": "Intel",          "00:22:FB": "Intel",
    "7C:B0:C2": "Intel",          "A0:88:B4": "Intel",
    "00:04:0F": "Cisco",          "00:0A:41": "Cisco",
    "00:0D:65": "Cisco",          "00:1B:2B": "Cisco",
    "00:26:CB": "Cisco",          "58:AC:78": "Cisco",
    "F4:CF:E2": "Cisco",
    "00:1D:0F": "ASUSTek",        "00:E0:18": "ASUSTek",
    "04:92:26": "ASUSTek",        "10:BF:48": "ASUSTek",
    "2C:56:DC": "ASUSTek",
    "00:1C:BF": "TP-Link",        "54:C8:0F": "TP-Link",
    "6C:5A:B0": "TP-Link",        "A0:F3:C1": "TP-Link",
    "C0:4A:00": "TP-Link",        "F4:EC:38": "TP-Link",
    "00:09:5B": "Netgear",        "00:14:6C": "Netgear",
    "00:1B:2F": "Netgear",        "20:E5:2A": "Netgear",
    "9C:D3:6D": "Netgear",
    "00:18:E7": "Ubiquiti",       "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",       "44:D9:E7": "Ubiquiti",
    "68:72:51": "Ubiquiti",       "78:8A:20": "Ubiquiti",
    "00:0F:B5": "Netopia",        "00:1C:10": "Mikrotik",
    "00:0C:42": "Mikrotik",       "2C:C8:1B": "Mikrotik",
    "00:1A:2B": "Fujitsu",        "00:26:B9": "Dell SecureWorks",
    "00:15:5D": "Microsoft Hyper-V",
    "00:03:FF": "Microsoft",
    "28:F0:76": "Samsung",        "8C:77:12": "Samsung",
    "CC:07:AB": "Samsung",        "F8:04:2E": "Samsung",
    "00:07:32": "Huawei",         "00:46:4B": "Huawei",
    "04:C0:6F": "Huawei",         "28:31:52": "Huawei",
    "00:1B:78": "HP",             "00:23:7D": "HP",
    "1C:C1:DE": "HP",             "3C:D9:2B": "HP",
    "94:57:A5": "HP",
}

def _oui_lookup(mac: str) -> str:
    """Return vendor name from first 3 octets of MAC, or empty string."""
    if not mac or len(mac) < 8:
        return ""
    oui = mac[:8].upper()
    return _OUI_TABLE.get(oui, "")

def _port_status(ip: str, port: int) -> str:
    """
    Determine the status of a single port:
      open     — connection accepted (connect_ex == 0)
      closed   — connection refused (errno 111 / WSAECONNREFUSED 10061)
      filtered — no response within timeout (everything else)
    """
    import errno as _errno
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TCP_TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                return "open"
            # ECONNREFUSED = 111 on Linux, 10061 on Windows
            if result in (111, 10061, _errno.ECONNREFUSED):
                return "closed"
            return "filtered"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "filtered"


def _scan_ports(ip: str, ports: list[int]) -> list[dict]:
    """
    Probe each port in the list.
    Returns open ports only (closed/filtered excluded from results
    but status field is set accurately for open ones).
    """
    open_ports = []
    for port in ports:
        status = _port_status(ip, port)
        if status == "open":
            label, category = PORT_MAP.get(port, ("Unknown", "infra"))
            open_ports.append({
                "port":     port,
                "status":   "open",
                "label":    label,
                "category": category,
                "banner":   _grab_banner(ip, port),
                "cves":     _lookup_cves(port),
            })
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
        {"ip": ip, "is_up": False, "hostname": "", "mac": "", "vendor": "", "ports": [], "os_guess": None, "os_confidence": None, "os_detail": None, "os_icon": None}
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
                open_ports    = future.result()
                hostname      = _resolve_hostname(ip)
                os_info       = _fingerprint_os(ip, open_ports, hostname)
                mac, vendor   = _get_mac(ip)
                results[ip_index[ip]] = {
                    "ip":           ip,
                    "is_up":        True,
                    "hostname":     hostname,
                    "mac":          mac,
                    "vendor":       vendor,
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