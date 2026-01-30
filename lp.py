<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PacketPulse | Advanced Network Intelligence</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;500;700&display=swap');

        :root {
            --bg: #030303;
            --accent: #00f2ff;
            --surface: #0a0a0a;
            --glass: rgba(255, 255, 255, 0.03);
            --border: rgba(255, 255, 255, 0.08);
            --text-dim: #94a3b8;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; scroll-behavior: smooth; }
        body { background-color: var(--bg); color: white; font-family: 'Space Grotesk', sans-serif; line-height: 1.6; }

        /* Background Visuals */
        .glow {
            position: fixed; top: 0; left: 50%; transform: translateX(-50%);
            width: 100vw; height: 100vh;
            background: radial-gradient(circle at 50% -10%, #0044ff22 0%, transparent 60%);
            z-index: -1;
        }

        nav { display: flex; justify-content: space-between; align-items: center; padding: 2rem 10%; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: rgba(3,3,3,0.8); backdrop-filter: blur(10px); z-index: 1000; }
        .logo { font-size: 1.5rem; font-weight: 700; color: var(--accent); letter-spacing: -1px; }

        /* Hero */
        header { height: 90vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; padding: 0 10%; }
        h1 { font-size: clamp(3.5rem, 10vw, 6rem); margin-bottom: 1.5rem; line-height: 0.9; font-weight: 700; }
        h1 span { color: var(--accent); text-shadow: 0 0 30px rgba(0, 242, 255, 0.3); }
        .subtitle { font-size: 1.4rem; color: var(--text-dim); max-width: 750px; margin-bottom: 3rem; }

        /* Stats Strip */
        .stats-bar { display: flex; justify-content: space-around; padding: 3rem 10%; background: var(--surface); border-y: 1px solid var(--border); }
        .stat-item { text-align: center; }
        .stat-item h2 { font-size: 2.5rem; color: var(--accent); }
        .stat-item p { color: var(--text-dim); text-transform: uppercase; font-size: 0.8rem; letter-spacing: 2px; }

        /* Product Showcase Section */
        .showcase { padding: 8rem 10%; display: flex; align-items: center; gap: 50px; }
        .showcase-text { flex: 1; }
        .showcase-visual { flex: 1.5; background: var(--glass); border: 1px solid var(--border); height: 400px; border-radius: 20px; display: flex; align-items: center; justify-content: center; position: relative; overflow: hidden; }
        .code-box { font-family: monospace; color: var(--accent); opacity: 0.6; padding: 20px; font-size: 0.9rem; }

        /* Tech Stack Grid */
        .stack-section { padding: 8rem 10%; background: #050505; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 2rem; margin-top: 4rem; }
        .card { padding: 3rem; background: var(--glass); border: 1px solid var(--border); border-radius: 24px; transition: 0.4s; }
        .card:hover { border-color: var(--accent); background: rgba(0, 242, 255, 0.02); }

        .cta-btn { background: white; color: black; padding: 1.2rem 3rem; border-radius: 50px; text-decoration: none; font-weight: 700; transition: 0.3s; }
        .cta-btn:hover { background: var(--accent); transform: scale(1.05); }

        footer { padding: 5rem 10%; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; color: var(--text-dim); }
    </style>
</head>
<body>
    <div class="glow"></div>
    <nav>
        <div class="logo">PacketPulse</div>
        <a href="#" class="cta-btn" style="padding: 0.6rem 1.5rem; font-size: 0.9rem;">LAUNCH CONSOLE</a>
    </nav>

    <header>
        <h1>Visibility is <span>Security.</span></h1>
        <p class="subtitle">PacketPulse is a dynamic network auditor designed to map, score, and secure every heartbeat of your local infrastructure.</p>
        <div style="display: flex; gap: 15px;">
            <a href="#features" class="cta-btn">EXPLORE TECH</a>
            <a href="#" style="color: white; padding: 1.2rem; text-decoration: none;">View Docs →</a>
        </div>
    </header>

    <div class="stats-bar">
        <div class="stat-item"><h2>< 1ms</h2><p>Response Latency</p></div>
        <div class="stat-item"><h2>65k+</h2><p>Ports Monitored</p></div>
        <div class="stat-item"><h2>100%</h2><p>Agentless Discovery</p></div>
    </div>

    <section id="features" class="showcase">
        <div class="showcase-text">
            <h2 style="font-size: 3rem; margin-bottom: 1.5rem;">Unmask your <br>Attack Surface.</h2>
            <p style="color: var(--text-dim); margin-bottom: 2rem;">Don't rely on static lists. PacketPulse interacts with Layer 2 and 3 to discover ghost assets that standard scanners miss.</p>
            <ul style="list-style: none; color: var(--accent);">
                <li style="margin-bottom: 10px;">✓ Fingerprint OS via TTL analysis</li>
                <li style="margin-bottom: 10px;">✓ Map MAC addresses to hardware vendors</li>
                <li style="margin-bottom: 10px;">✓ Identify exposed IoT protocols</li>
            </ul>
        </div>
        <div class="showcase-visual">
            <div class="code-box">
                [SYSTEM_PROBE_ACTIVE]<br>
                > scanning 192.168.1.0/24...<br>
                > found: 00:0c:29:4b:8c:11 (VMware Inc)<br>
                > critical: port 445 open (SMB)<br>
                > risk_score: 88/100
            </div>
        </div>
    </section>
    
    

    <section class="stack-section">
        <h2 style="text-align: center; font-size: 3rem;">The Pulse Stack</h2>
        <div class="grid">
            <div class="card">
                <h3>Asset Inventory</h3>
                <p>Maintain a "Single Source of Truth" for your hardware. Track MAC addresses, hostnames, and OS versions automatically.</p>
            </div>
            <div class="card">
                <h3>Dynamic Risk</h3>
                <p>Every open port is weighted. Our engine calculates a 1/100 score so you know exactly what to fix first.</p>
            </div>
            <div class="card">
                <h3>Docker Ready</h3>
                <p>Deploy in seconds. Optimized for high-performance host networking to bypass virtual bridge limitations.</p>
            </div>
        </div>
    </section>

    <footer>
        <div class="logo" style="font-size: 1rem; color: white;">PACKETPULSE // 2026</div>
        <div>Built for Defenders. Agentless. Fast. Open.</div>
    </footer>
</body>
</html>