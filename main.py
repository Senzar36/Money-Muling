import uvicorn
import networkx as nx
import pandas as pd
from io import BytesIO
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

def init_db():
    print("Forensic Database Initialized.")

class MuleAnalyzer:
    @staticmethod
    def process_csv_with_graph(file_contents):
        try:
            df = pd.read_csv(BytesIO(file_contents))
            df.columns = [str(c).strip().lower() for c in df.columns]
        except Exception as e:
            raise ValueError(f"Invalid CSV format: {str(e)}")
        
        required = ['sender_id', 'receiver_id', 'amount']
        for col in required:
            if col not in df.columns:
                raise ValueError(f"Missing mandatory column: {col}")

        G = nx.DiGraph()
        for _, row in df.iterrows():
            G.add_edge(str(row['sender_id']), str(row['receiver_id']), amount=float(row['amount']))
        
        suspicious_accounts = {}
        fraud_rings = []

        try:
            cycles = list(nx.simple_cycles(G))
            for idx, ring in enumerate(cycles):
                ring_id = f"RING_{idx+1:03}"
                ring_members = [str(node) for node in ring]
                fraud_rings.append({"ring_id": ring_id, "member_accounts": ring_members, "risk_score": 98.0})
                for acc in ring_members:
                    suspicious_accounts[acc] = {"score": 98.0, "pattern": "Circular Laundering", "ring": ring_id, "color": "#ff4d4d"}
        except: pass

        for node in G.nodes():
            node_str = str(node)
            if node_str in suspicious_accounts: continue
            degree = G.degree(node)
            if degree >= 5:
                suspicious_accounts[node_str] = {"score": 55.0, "pattern": "High-Activity Hub", "ring": "N/A", "color": "#ffcc00"}
            else:
                suspicious_accounts[node_str] = {"score": 15.0, "pattern": "Standard Path", "ring": "N/A", "color": "#7cfc00"}

        cy_elements = []
        for node in G.nodes():
            info = suspicious_accounts.get(str(node))
            cy_elements.append({'data': {'id': str(node), 'label': str(node), 'color': info['color'], 'score': info['score'], 'pattern': info['pattern'], 'ring': info['ring']}})
        for u, v, d in G.edges(data=True):
            cy_elements.append({'data': {'source': str(u), 'target': str(v), 'amount': d.get('amount', 0)}})

        return {
            "fraud_rings": fraud_rings,
            "summary": {"total_nodes": int(G.number_of_nodes()), "flagged_rings": int(len(fraud_rings))},
            "graph_data": cy_elements
        }

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

HTML_CONTENT = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Quasar | RIFT 2026</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.23.0/cytoscape.min.js"></script>
    <script src="https://polyfill.io/v3/polyfill.min.js?features=es6"></script>
    <script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>
    <style>
        :root { --accent: #00f2fe; --bg: #0b0e14; --danger: #ff4d4d; --warning: #ffcc00; --safe: #7cfc00; }
        body { margin:0; font-family: "Segoe UI", sans-serif; background: var(--bg); color:white; overflow:hidden; }
        .page { position: absolute; width:100%; height:100vh; display:flex; justify-content:center; align-items:center; opacity:0; visibility:hidden; transition:0.5s; }
        .active { opacity:1; visibility:visible; }
        
        .card { text-align:center; width: 600px; padding:50px; background:rgba(255,255,255,0.05); border-radius:40px; border:1px solid rgba(0,242,254,0.2); backdrop-filter:blur(20px); }
        .feature-box { text-align: left; background: rgba(0,0,0,0.3); padding: 25px; border-radius: 20px; margin: 25px 0; border: 1px solid rgba(255,255,255,0.05); }
        .feature-list { list-style: none; padding: 0; margin: 0; }
        .feature-list li { margin-bottom: 12px; font-size: 15px; display: flex; align-items: center; }
        .feature-list li span { margin-right: 15px; font-size: 20px; }

        .app-container { width:98%; height:94%; display:grid; grid-template-columns:420px 1fr; gap:20px; padding:20px; }
        .sidebar { background:rgba(255,255,255,0.05); padding:25px; border-radius:25px; overflow-y:auto; border:1px solid rgba(255,255,255,0.1); display: flex; flex-direction: column; }
        #cy { background:rgba(0,0,0,0.3); border-radius:25px; position:relative; }
        
        #tooltip { 
            position: absolute; display: none; background: rgba(10,10,15,0.95); 
            border: 1px solid var(--accent); padding: 12px; border-radius: 10px; 
            z-index: 1000; font-size: 13px; pointer-events: none; backdrop-filter: blur(10px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.5);
        }

        button { background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); border:none; padding:18px; color:#000; border-radius:15px; cursor:pointer; font-weight:800; width:100%; margin:10px 0; text-transform: uppercase; letter-spacing: 1px; }
        .btn-outline { background: transparent; border: 2px solid var(--accent); color: var(--accent); font-size: 11px; margin-top: auto; }
        
        table { width:100%; border-collapse:separate; border-spacing: 0 8px; font-size:11px; margin-top:10px; }
        td { padding:10px; background: rgba(255,255,255,0.03); border-radius: 8px; }

        .modal { display:none; position:fixed; z-index:2000; left:0; top:0; width:100%; height:100%; background:rgba(0,0,0,0.95); align-items:center; justify-content:center; }
        .modal-content { background:#1a1d23; padding:40px; border-radius:30px; border:1px solid var(--accent); max-width:800px; text-align:left; }
        .math-block { background: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px; margin: 15px 0; border: 1px solid rgba(255,255,255,0.1); }
    </style>
</head>
<body>
    <div id="tooltip"></div>

    <div id="methodModal" class="modal">
        <div class="modal-content">
            <h2 style="color:var(--accent); margin-top:0;">Forensic Risk Mathematics</h2>
            <div class="math-block">
                <b style="color:var(--danger)">1. Circularity Logic (Red):</b><br>
                \[ v \in \{v_0, v_1, ..., v_k\} \text{ where } v_0 = v_k \]
            </div>
            <div class="math-block">
                <b style="color:var(--warning)">2. Centrality Logic (Yellow):</b><br>
                \[ C_D(v) = \text{deg}_{in}(v) + \text{deg}_{out}(v) \geq 5 \]
            </div>
            <button onclick="closeModal()">Close</button>
        </div>
    </div>

    <div id="welcome" class="page active">
        <div class="card">
            <h1 style="color:var(--accent); font-size:52px; margin:0 0 10px 0;">Team Quasar</h1>
            <p style="opacity: 0.8; font-size: 18px;">Financial Forensic Intelligence Dashboard</p>
            
            <div class="feature-box">
                <ul class="feature-list">
                    <li><span>🔍</span> Graph Analysis for Money Muling</li>
                    <li><span>📊</span> Interactive Ring & Hub Visualization</li>
                    <li><span>⚠️</span> Real-time Risk Scoring & Hover Details</li>
                </ul>
            </div>
            
            <button onclick="showDash()">Enter Command Center</button>
        </div>
    </div>

    <div id="dashboard" class="page">
        <div class="app-container">
            <div class="sidebar">
                <h2 style="color:var(--accent);">🛡️ forensic_scan</h2>
                <input type="file" id="csvFile" accept=".csv" style="margin-bottom:15px; color:white; font-size:12px;">
                <button onclick="runAnalysis()">Execute Analysis</button>
                <div id="sum" style="font-size:12px; margin:10px 0; color:var(--accent); font-weight:bold;"></div>
                
                <div style="flex-grow: 1; overflow-y: auto;">
                    <table id="ringTable">
                        <thead><tr style="text-align:left; opacity:0.5; font-size:10px;"><th>RING ID</th><th>RISK</th><th>ACCOUNTS</th></tr></thead>
                        <tbody></tbody>
                    </table>
                </div>

                <button class="btn-outline" onclick="openModal()">View Forensic Mathematics</button>
            </div>
            <div id="cy"></div>
        </div>
    </div>

    <script>
        function showDash() { document.getElementById('welcome').classList.remove('active'); document.getElementById('dashboard').classList.add('active'); }
        function openModal() { document.getElementById('methodModal').style.display = 'flex'; }
        function closeModal() { document.getElementById('methodModal').style.display = 'none'; }

        async function runAnalysis() {
            const file = document.getElementById('csvFile').files[0];
            if(!file) return alert("Select CSV");
            const fd = new FormData(); fd.append("file", file);
            const res = await fetch('/upload', {method:'POST', body:fd});
            const data = await res.json();
            
            document.getElementById('sum').innerText = `Nodes: ${data.summary.total_nodes} | Critical Rings: ${data.summary.flagged_rings}`;
            
            const tbody = document.getElementById('ringTable').querySelector('tbody');
            tbody.innerHTML = data.fraud_rings.map(r => `
                <tr>
                    <td style="color:var(--danger); font-weight:bold;">${r.ring_id}</td>
                    <td>${r.risk_score}%</td>
                    <td style="font-size:9px; opacity:0.8;">${r.member_accounts.join(', ')}</td>
                </tr>
            `).join('');

            renderGraph(data.graph_data);
        }

        function renderGraph(els) {
            const cy = cytoscape({
                container: document.getElementById('cy'),
                elements: els,
                style: [
                    { selector: 'node', style: { 
                        'label':'data(id)', 'color':'#fff', 'font-size':'10px', 
                        'background-color': 'data(color)', 'width': 30, 'height': 30, 
                        'text-valign': 'center', 'text-outline-width': 2, 'text-outline-color': '#000'
                    }},
                    { selector: 'edge', style: { 
                        'width':2, 'line-color':'#555', 'target-arrow-shape':'triangle', 
                        'curve-style':'bezier', 'target-arrow-color': '#555', 'opacity': 0.6
                    }}
                ],
                layout: { name: 'cose', padding: 50 }
            });

            const tt = document.getElementById('tooltip');
            cy.on('mouseover', 'node', e => {
                const d = e.target.data();
                tt.style.display = 'block';
                tt.innerHTML = `
                    <div style="color:var(--accent); font-weight:bold; margin-bottom:5px;">Account Profile</div>
                    <b>ID:</b> ${d.id}<br>
                    <b>Risk Score:</b> <span style="color:${d.color}">${d.score}%</span><br>
                    <b>Pattern:</b> ${d.pattern}<br>
                    <b>Ring:</b> ${d.ring}
                `;
            });

            cy.on('mousemove', 'node', e => {
                tt.style.top = (e.renderedPosition.y + 15) + 'px';
                tt.style.left = (e.renderedPosition.x + 15) + 'px';
            });

            cy.on('mouseout', 'node', () => tt.style.display = 'none');
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home(): return HTML_CONTENT

@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    try:
        content = await file.read()
        return MuleAnalyzer.process_csv_with_graph(content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)