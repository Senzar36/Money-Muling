import uvicorn
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from analyzer import MuleAnalyzer
from database import init_db
import pandas as pd
from io import BytesIO

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
engine = MuleAnalyzer()

current_analysis = {"full_registry": {}, "fraud_rings": [], "graph_elements": []}

HTML_CONTENT = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>QUASAR // Forensic Intelligence Suite</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.23.0/cytoscape.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --accent: #00f2fe;
            --accent-soft: rgba(0, 242, 254, 0.1);
            --danger: #ff4d4d;
            --bg: #030508;
            --surface: #0a0d12;
            --border: rgba(255, 255, 255, 0.1);
        }

        * { transition: all 0.15s ease-out; box-sizing: border-box; }
        body { margin: 0; font-family: 'Inter', sans-serif; background-color: var(--bg); color: #d1d5db; height: 100vh; overflow: hidden; }

        #firewall { position: fixed; inset: 0; background: radial-gradient(circle, #0f172a 0%, #030508 100%); z-index: 10000; display: flex; align-items: center; justify-content: center; flex-direction: column; }
        .login-card { width: 480px; padding: 50px; background: var(--surface); border: 1px solid var(--accent); border-radius: 4px; text-align: center; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }

        #intelPortal { position: fixed; inset: 0; background: var(--bg); z-index: 10001; display: none; padding: 60px; overflow-y: auto; }
        .intel-container { max-width: 900px; margin: 0 auto; padding-bottom: 100px; }

        nav { 
            position: fixed; top: 0; width: 100%; height: 60px; background: #000; 
            border-bottom: 1px solid var(--border); display: flex; align-items: center; padding: 0 30px; z-index: 9000;
        }
        .nav-link { margin-right: 25px; font-family: 'JetBrains Mono'; font-size: 11px; cursor: pointer; color: #71717a; text-transform: uppercase; letter-spacing: 1px; padding: 10px 0; }
        .nav-link.active { color: var(--accent); border-bottom: 2px solid var(--accent); }

        .page { position: absolute; inset: 0; display: none; padding-top: 60px; height: 100vh; background: var(--bg); }
        .page.active { display: block; }
        .container { display: grid; grid-template-columns: 420px 1fr; height: calc(100vh - 60px); }
        
        aside { background: var(--surface); border-right: 1px solid var(--border); padding: 25px; display: flex; flex-direction: column; gap: 20px; overflow-y: auto; }
        main { position: relative; background: #000; height: 100%; padding-bottom: 100px; } 

        .card { background: #111827; border: 1px solid var(--border); padding: 25px; border-radius: 4px; line-height: 1.6; }
        .label { font-size: 10px; color: var(--accent); letter-spacing: 2px; text-transform: uppercase; margin-bottom: 12px; display: block; font-weight: 700; }
        
        button { background: var(--accent); color: #000; border: none; padding: 14px; font-weight: bold; cursor: pointer; border-radius: 2px; font-family: 'JetBrains Mono'; width: 100%; text-transform: uppercase; }
        .btn-sec { background: transparent; border: 1px solid #3f3f46; color: #fff; margin-top: 10px; }
        
        input[type="text"], input[type="password"] { width: 100%; padding: 14px; background: #000; border: 1px solid #27272a; color: var(--accent); font-family: 'JetBrains Mono'; outline: none; }

        #cy { width: 100%; height: 100%; }
        #tooltip { position: absolute; display: none; background: #09090b; border: 1px solid var(--accent); padding: 15px; z-index: 1001; pointer-events: none; font-family: 'JetBrains Mono'; font-size: 11px; color: #fff; }
        
        table { width: 100%; border-collapse: collapse; font-family: 'JetBrains Mono'; font-size: 11px; }
        th { text-align: left; color: #71717a; padding: 10px 5px; border-bottom: 1px solid #27272a; }
        td { padding: 10px 5px; border-bottom: 1px solid #18181b; }
    </style>
</head>
<body>

    <div id="firewall">
        <div class="login-card">
            <h1 style="color: #fff; font-family: 'JetBrains Mono'; margin: 0; font-size: 28px;">QUASAR // CORE</h1>
            <p style="font-size: 10px; letter-spacing: 5px; color: var(--accent); margin: 10px 0 40px 0;">CENTRAL INTELLIGENCE UNIT</p>
            <input type="password" id="accessKey" placeholder="ENCRYPTION_KEY" style="text-align:center; margin-bottom: 15px;">
            <button onclick="unlock()">AUTHENTICATE ACCESS</button>
            <button class="btn-sec" onclick="toggleIntel(true)">SYSTEM DOCUMENTATION</button>
            <p id="err" style="color:var(--danger); font-size:12px; margin-top:20px; font-family: 'JetBrains Mono';"></p>
        </div>
        <p style="margin-top: 40px; font-size: 11px; color: #52525b; font-family: 'JetBrains Mono';">V.1.0.4 | STABLE_BUILD | 30_DAY_SPRINT</p>
    </div>

    <div id="intelPortal">
        <div class="intel-container">
            <button style="width: auto; margin-bottom: 50px;" onclick="toggleIntel(false)">← BACK TO TERMINAL</button>
            
            <h1 style="color: var(--accent); font-family: 'JetBrains Mono'; font-size: 32px; margin-bottom: 30px;">FORENSIC INTELLIGENCE OVERVIEW</h1>
            
            <div class="card">
                <span class="label">Comprehensive Definition: Money Mules</span>
                <p>A <b>Money Mule</b> is a critical node in the financial laundering chain. These individuals receive funds from criminal activities (such as phishing, business email compromise, or fraud) and transfer them to another account or convert them into assets like cryptocurrency. By using mules, criminal organizations create a "buffer" that breaks the direct link between the victim and the perpetrator, making it nearly impossible for traditional linear tracking to succeed.</p>
            </div>

            <div class="card">
                <span class="label">Detection Methodology</span>
                <p>The QUASAR engine identifies these actors through three distinct algorithmic layers:</p>
                <ul style="line-height: 2;">
                    <li><b>Cycle Enumeration:</b> Identifying <i>Circular Laundering</i> where funds return to a point of origin after passing through 3-5 intermediary accounts to simulate legitimate trade volume.</li>
                    <li><b>Smurfing Identification:</b> Detecting accounts that receive a high frequency of small-value deposits from disparate sources, which are then moved in a single large "burst" to a high-tier node.</li>
                    <li><b>Topology Analysis:</b> Measuring <i>Betweenness Centrality</i> to find the "hubs" that facilitate the majority of the network's illicit flow.</li>
                </ul>
            </div>

            <div class="card">
                <span class="label">Future Development Scope</span>
                <p>Planned modules for subsequent development cycles:</p>
                <ul style="line-height: 2;">
                    <li><b>AI Predictive Scoring:</b> Implementation of Random Forest and LSTM models to flag suspicious patterns before the first transaction cycle is completed.</li>
                    <li><b>Cross-Border API Integration:</b> Real-time SWIFT and ISO 20022 data parsing for international asset tracking.</li>
                    <li><b>Hardware Encryption:</b> Biometric dashboard access and hardware-level AES-256 encryption for investigative logs.</li>
                </ul>
            </div>
        </div>
    </div>

    <nav id="mainNav" style="display:none;">
        <div style="color: var(--accent); font-weight: 800; font-family: 'JetBrains Mono'; margin-right: 50px; font-size: 18px;">QUASAR</div>
        <div class="nav-link active" onclick="showPage('home', this)">1.0 Dashboard</div>
        <div class="nav-link" onclick="showPage('entitySearch', this)">2.0 Entity Search</div>
        <div class="nav-link" onclick="showPage('compliance', this)">3.0 Compliance</div>
        <div class="nav-link" onclick="showPage('api', this)">4.0 API Gateway</div>
    </nav>

    <div id="home" class="page active" style="display:none;">
        <div class="container">
            <aside>
                <div class="card">
                    <span class="label">Money Mule Intelligence</span>
                    <p style="font-size: 12px; margin: 0;"><b>Definition:</b> Intermediaries used to disguise illicit money trails.<br><br><b>Detection:</b> Our engine identifies circular paths and smurfing hubs that deviate from standard commercial behavior via graph-topology mapping.</p>
                </div>

                <div class="card">
                    <span class="label">Forensic Ingestion</span>
                    <input type="file" id="csvFile" style="font-size: 11px; margin-bottom: 15px; color: #fff;">
                    <button onclick="analyze()">EXECUTE DEEP SCAN</button>
                </div>

                <div class="card" style="flex-grow: 1; overflow-y: auto;">
                    <span class="label">Flagged Clusters</span>
                    <table>
                        <thead><tr><th>ID</th><th>RISK</th></tr></thead>
                        <tbody id="resultsBody"></tbody>
                    </table>
                </div>
            </aside>
            <main>
                <div id="cy"></div>
                <div id="tooltip"></div>
            </main>
        </div>
    </div>

    <div id="entitySearch" class="page">
        <div class="intel-container">
            <h1 style="color: var(--accent); font-family: 'JetBrains Mono';">ENTITY INVESTIGATION</h1>
            <div class="card">
                <span class="label">Query Engine</span>
                <div style="display: flex; gap: 10px;">
                    <input type="text" id="searchInput" placeholder="ENTER ENTITY_ID (e.g. ACC_00890)">
                    <button style="width: 150px;" onclick="queryEntity()">QUERY</button>
                </div>
            </div>
            <div class="card" id="entityResult">
                <span class="label">Risk Profile Summary</span>
                <p style="color: #71717a;">Search for an entity to view KYC status, historical transaction frequency, and network influence scores.</p>
            </div>
        </div>
    </div>

    <div id="compliance" class="page">
        <div class="intel-container">
            <h1 style="color: var(--accent); font-family: 'JetBrains Mono';">REGULATORY COMPLIANCE AUDIT</h1>
            <div class="card">
                <span class="label">Automated SAR Filing Status</span>
                <table>
                    <tr><th>REGULATORY BODY</th><th>PROTOCOL</th><th>STATUS</th></tr>
                    <tr><td>FinCEN</td><td>Rule 504.b</td><td style="color: #10b981;">OPERATIONAL</td></tr>
                    <tr><td>FATF</td><td>Recommendation 16</td><td style="color: var(--danger);">UNDER REVIEW</td></tr>
                </table>
            </div>
        </div>
    </div>

    <div id="api" class="page">
        <div class="intel-container">
            <h1 style="color: var(--accent); font-family: 'JetBrains Mono';">API GATEWAY & WEBHOOKS</h1>
            <div class="card">
                <span class="label">Active Endpoint</span>
                <code style="color: #10b981; font-size: 16px;">POST /api/v1/forensics/analyze</code>
            </div>
            <div class="card">
                <span class="label">Access Configuration</span>
                <p><b>Bearer Token:</b> <span style="color: var(--accent); font-family: 'JetBrains Mono';">qz_prod_882x_stable</span></p>
                <button class="btn-sec" style="width: auto; padding: 10px 20px;">Rotate Keys</button>
            </div>
        </div>
    </div>

    <script>
        function showPage(id, el) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            document.getElementById(id).classList.add('active');
            el.classList.add('active');
        }

        function toggleIntel(show) { document.getElementById('intelPortal').style.display = show ? 'block' : 'none'; }

        function unlock() {
            if(document.getElementById('accessKey').value === "QUASAR") {
                document.getElementById('firewall').style.display = 'none';
                document.getElementById('mainNav').style.display = 'flex';
                document.getElementById('home').style.display = 'block';
            } else {
                document.getElementById('err').innerText = "ERROR: INVALID ENCRYPTION KEY";
            }
        }

        async function analyze() {
            const file = document.getElementById('csvFile').files[0];
            if(!file) return;
            const fd = new FormData(); fd.append("file", file);
            const res = await fetch('/upload', {method:'POST', body:fd});
            const data = await res.json();
            const tbody = document.getElementById('resultsBody');
            tbody.innerHTML = data.fraud_rings.map(r => `<tr><td>${r.ring_id}</td><td style="color:var(--danger); font-weight:bold;">${r.score}%</td></tr>`).join('');
            render(data.graph_elements);
        }

        async function queryEntity() {
            const id = document.getElementById('searchInput').value.trim();
            if(!id) return;
            const res = await fetch(`/search?id=${encodeURIComponent(id)}`);
            const data = await res.json();
            const box = document.getElementById('entityResult');
            
            if(data.found) {
                const color = data.details.score > 80 ? 'var(--danger)' : (data.details.score > 40 ? '#ffcc00' : '#00ff00');
                box.innerHTML = `
                    <span class="label" style="color:${color}">Forensic Record Found: ${id}</span>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:25px; margin-top:15px;">
                        <div class="card" style="background:#000; margin:0; padding:15px;">
                            <p style="font-size:11px; color:#555; margin:0;">RISK CLASSIFICATION</p>
                            <p style="font-size:18px; color:${color}; font-weight:bold; margin:5px 0;">${data.details.pattern}</p>
                            <p style="font-size:11px; margin:0;">Aggregated Score: ${data.details.score}%</p>
                        </div>
                        <div class="card" style="background:#000; margin:0; padding:15px;">
                            <p style="font-size:11px; color:#555; margin:0;">ALGORITHMIC RATIONALE</p>
                            <p style="font-size:13px; margin:10px 0;">${data.details.math}</p>
                            <p style="font-size:10px; color:#444; margin:0;">KYC_STATUS: VERIFIED_PROVISIONAL</p>
                        </div>
                    </div>
                `;
            } else {
                box.innerHTML = `<span class="label" style="color:var(--danger)">No Match Found</span><p>Entity <b>${id}</b> was not found. Ensure CSV is uploaded and ID is correct.</p>`;
            }
        }

        function render(els) {
            const cy = cytoscape({
                container: document.getElementById('cy'),
                elements: els,
                style: [
                    { selector: 'node', style: { 'label': 'data(id)', 'background-color': 'data(color)', 'color': '#fff', 'font-size': '8px', 'width': 24, 'height': 24, 'text-valign': 'center', 'text-outline-width': 1, 'text-outline-color': '#000' }},
                    { selector: 'edge', style: { 'width': 1.5, 'line-color': '#27272a', 'target-arrow-shape': 'triangle', 'target-arrow-color': '#27272a', 'curve-style': 'bezier', 'opacity': 0.8 }}
                ],
                layout: { name: 'cose', padding: 150, nodeRepulsion: 15000 } 
            });

            cy.on('mouseover', 'node', e => {
                const d = e.target.data();
                const tt = document.getElementById('tooltip');
                tt.style.display = 'block';
                tt.innerHTML = `ENTITY: ${d.id}<br>RISK: ${d.score}%<br>CLASS: ${d.pattern}`;
            });
            cy.on('mousemove', 'node', e => {
                const tt = document.getElementById('tooltip');
                tt.style.top = (e.renderedPosition.y + 75) + 'px';
                tt.style.left = (e.renderedPosition.x + 20) + 'px';
            });
            cy.on('mouseout', 'node', () => document.getElementById('tooltip').style.display = 'none');
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home(): return HTML_CONTENT

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    global current_analysis
    df = pd.read_csv(BytesIO(await file.read()))
    current_analysis = engine.process_data(df)
    return current_analysis

@app.get("/search")
async def search(id: str):
    registry = current_analysis.get("full_registry", {})
    match = registry.get(id)
    if match:
        return {"found": True, "details": match}
    return {"found": False}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)