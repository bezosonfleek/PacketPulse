import socket
import json
import platform
import subprocess
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

# --- SCANNER LOGIC ---

def ping_host(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout = '1000' if platform.system().lower() == 'windows' else '1'
    flag = '-w' if platform.system().lower() == 'windows' else '-W'
    command = ['ping', param, '1', flag, timeout, ip]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) == 0

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.8)
            if s.connect_ex((ip, port)) == 0:
                s.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
                banner = s.recv(1024).decode(errors='ignore').splitlines()
                return {"port": port, "banner": banner[0][:50] if banner else "Open (No Banner)"}
    except: pass
    return None

def run_network_scan(subnet):
    results = []
    # Generates IPs .1 through .50 based on user input
    ips = [f"{subnet}.{i}" for i in range(1, 51)]
    
    print(f"[*] Backend: Scanning user-defined subnet: {subnet}.0/24")

    def check_ip(ip):
        if ping_host(ip):
            found_ports = []
            for port in [21, 22, 80, 443, 445, 3389, 8080]:
                p_res = scan_port(ip, port)
                if p_res: found_ports.append(p_res)
            return {"ip": ip, "ports": found_ports}
        return None

    with ThreadPoolExecutor(max_workers=30) as executor:
        scan_data = list(executor.map(check_ip, ips))
        results = [item for item in scan_data if item]
    
    return results

# --- WEB SERVER LOGIC ---

class ScannerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url_parsed = urllib.parse.urlparse(self.path)
        
        if url_parsed.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.get_html().encode())
            
        elif url_parsed.path == '/run-scan':
            # Extract 'subnet' from the URL query string
            query = urllib.parse.parse_qs(url_parsed.query)
            user_subnet = query.get('subnet', ['192.168.1'])[0] # Default if empty
            
            data = run_network_scan(user_subnet)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

    def get_html(self):
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dynamic Vulnerability Scanner</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
                .container { max-width: 900px; margin: auto; }
                .config-panel { background: #1e293b; padding: 25px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #334155; }
                input { background: #0f172a; border: 1px solid #38bdf8; color: white; padding: 12px; border-radius: 6px; width: 250px; margin-right: 10px; font-size: 16px; }
                button { background: #38bdf8; color: #0f172a; padding: 12px 24px; border: none; cursor: pointer; border-radius: 6px; font-weight: bold; font-size: 16px; transition: 0.3s; }
                button:hover { background: #7dd3fc; transform: translateY(-2px); }
                .card { background: #1e293b; border-left: 5px solid #10b981; padding: 20px; margin: 15px 0; border-radius: 8px; animation: fadeIn 0.5s ease; }
                .vuln { border-left-color: #f43f5e; }
                .port-tag { display: inline-block; background: #334155; padding: 6px 12px; border-radius: 4px; margin: 5px; font-family: monospace; font-size: 13px; color: #fbbf24; border: 1px solid #475569; }
                @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
                #status { margin: 15px 0; color: #94a3b8; font-style: italic; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Dynamic Vulnerability Scanner</h1>
                
                <div class="config-panel">
                    <label>Enter Subnet Prefix (e.g., 192.168.1):</label><br><br>
                    <input type="text" id="subnetInput" placeholder="192.168.1">
                    <button onclick="startScan()">Start Discovery</button>
                </div>

                <div id="status">Enter a subnet and click Start.</div>
                <div id="results"></div>
            </div>

            <script>
                async function startScan() {
                    const subnet = document.getElementById('subnetInput').value;
                    if (!subnet) { alert('Please enter a subnet!'); return; }

                    const status = document.getElementById('status');
                    const results = document.getElementById('results');
                    
                    status.innerHTML = `<strong>Scanning ${subnet}.1 to ${subnet}.50...</strong> This may take a minute.`;
                    results.innerHTML = '';
                    
                    try {
                        const response = await fetch(`/run-scan?subnet=${subnet}`);
                        const data = await response.json();
                        
                        status.innerText = `Scan Complete. Found ${data.length} active devices.`;
                        
                        if (data.length === 0) {
                            results.innerHTML = '<div class="card">No devices found. Ensure the subnet is correct and devices are discoverable.</div>';
                        }

                        data.forEach(host => {
                            const isVuln = host.ports.length > 0;
                            let hostDiv = document.createElement('div');
                            hostDiv.className = isVuln ? 'card vuln' : 'card';
                            
                            let portHtml = host.ports.map(p => `<div class="port-tag">Port ${p.port} | ${p.banner}</div>`).join('');
                            
                            hostDiv.innerHTML = `
                                <div style="font-size: 1.2em; font-weight: bold; margin-bottom: 10px;">Host: ${host.ip}</div>
                                ${isVuln ? '<span style="color:#f43f5e; font-size: 0.9em;">⚠ Services Found:</span><br>' : '<span style="color:#94a3b8;">No common ports open.</span>'}
                                ${portHtml}
                            `;
                            results.appendChild(hostDiv);
                        });
                    } catch (err) {
                        status.innerText = 'Error: Communication with backend failed.';
                        console.error(err);
                    }
                }
            </script>
        </body>
        </html>
        """

if __name__ == '__main__':
    # Running on localhost:8000
    server = HTTPServer(('localhost', 8000), ScannerHandler)
    print("Scanner UI initialized at http://localhost:8000")
    server.serve_forever()
