import uvicorn
import networkx as nx
import pandas as pd
import time
from io import BytesIO
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from database import init_db, save_mule

class MuleAnalyzer:
    @staticmethod
    def process_csv_with_graph(file_contents):
        start_time = time.time()
        try:
            df = pd.read_csv(BytesIO(file_contents))
            df.columns = [str(c).strip().lower() for c in df.columns]
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        except Exception as e:
            raise ValueError(f"Invalid CSV format: {str(e)}")
        
        G = nx.DiGraph()
        for _, row in df.iterrows():
            G.add_edge(str(row['sender_id']), str(row['receiver_id']), 
                       amount=float(row['amount']), timestamp=row['timestamp'])
        
        communities = list(nx.weakly_connected_components(G))
        community_map = {node: idx for idx, comm in enumerate(communities) for node in comm}

        suspicious_accounts = {}
        fraud_rings = []

        # 1. CYCLE DETECTION + VELOCITY
        try:
            cycles = list(nx.simple_cycles(G))
            for idx, ring in enumerate(cycles):
                if 3 <= len(ring) <= 6:
                    ring_id = f"RING_{idx+1:03}"
                    ring_members = [str(node) for node in ring]
                    ring_txns = df[df['sender_id'].isin(ring_members) & df['receiver_id'].isin(ring_members)]
                    time_span = (ring_txns['timestamp'].max() - ring_txns['timestamp'].min()).total_seconds()
                    
                    risk_score = 99.0 if time_span < 7200 else 95.0
                    pattern = "High-Velocity Layering" if time_span < 7200 else "Circular Routing"
                    
                    fraud_rings.append({"ring_id": ring_id, "member_accounts": ring_members, "pattern_type": pattern, "risk_score": risk_score})
                    for acc in ring_members:
                        suspicious_accounts[acc] = {"score": risk_score, "pattern": pattern, "ring": ring_id, "linked_to": [m for m in ring_members if m != acc]}
        except: pass

        # 2. HUB DETECTION
        for node in G.nodes():
            in_deg, out_deg = G.in_degree(node), G.out_degree(node)
            if (in_deg >= 8 or out_deg >= 8) and str(node) not in suspicious_accounts:
                suspicious_accounts[str(node)] = {"score": 88.0, "pattern": "Aggregation Hub", "ring": "N/A", "linked_to": []}

        colors = ["#00f2fe", "#ff00ff", "#7cfc00", "#ffa500", "#ff4500", "#da70d6"]

        cy_elements = []
        for node in G.nodes():
            node_str = str(node)
            is_susp = node_str in suspicious_accounts
            
            if is_susp:
                info = suspicious_accounts[node_str]
            else:
                # Calculate baseline risk for normal accounts based on activity levels
                activity_score = min(25.0, (G.degree(node) * 5.0)) 
                info = {"score": activity_score, "pattern": "Normal Activity", "ring": "None", "linked_to": []}
            
            cy_elements.append({
                'data': {
                    'id': node_str, 
                    'label': node_str,
                    'is_suspicious': is_susp,
                    'comm_color': colors[community_map.get(node, 0) % len(colors)] if not is_susp else "#ff4d4d",
                    'score': info['score'],
                    'pattern': info['pattern'],
                    'ring': info['ring'],
                    'linked_members': ", ".join(info['linked_to'])
                }
            })
        
        for u, v, d in G.edges(data=True):
            cy_elements.append({'data': {'source': str(u), 'target': str(v), 'amount': d.get('amount', 0)}})

        return {
            "fraud_rings": fraud_rings,
            "summary": {"total_accounts": int(G.number_of_nodes()), "flagged": int(len(suspicious_accounts)), "syndicates": int(len(communities))},
            "graph_data": cy_elements
        }

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db(); yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

HTML_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <title>Quasar | RIFT 2026</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.23.0/cytoscape.min.js"></script>
    <style>
        :root { --accent: #00f2fe; --bg: #0b0e14; --panel: rgba(255,255,255,0.05); --danger: #ff4d4d; }
        body { margin:0; font-family: "Segoe UI", sans-serif; background: var(--bg); color:white; overflow:hidden; }
        .page { position: absolute; width:100%; height:100vh; display:flex; justify-content:center; align-items:center; opacity:0; visibility:hidden; transition:0.5s; }
        .active { opacity:1; visibility:visible; }
        .card { text-align:center; max-width:750px; padding:60px; background:var(--panel); border-radius:40px; border:1px solid rgba(0,242,254,0.2); backdrop-filter:blur(20px); }
        .app-container { width:98%; height:94%; display:grid; grid-template-columns:450px 1fr; gap:20px; padding:20px; }
        .sidebar { background:var(--panel); padding:25px; border-radius:25px; overflow-y:auto; border:1px solid rgba(255,255,255,0.1); }
        #cy { background:rgba(0,0,0,0.3); border-radius:25px; position:relative; }
        #tooltip { position: absolute; display: none; background: rgba(10,10,15,0.98); border: 1px solid var(--accent); padding: 15px; border-radius: 12px; z-index: 1000; font-size: 12px; pointer-events: none; width: 260px; box-shadow: 0 10px 30px rgba(0,0,0,0.8); }
        button { background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); border:none; padding:16px; color:#000; border-radius:15px; cursor:pointer; font-weight:800; width:100%; margin:15px 0; text-transform: uppercase; }
        table { width:100%; border-collapse:separate; border-spacing: 0 8px; font-size:11px; }
        th { text-align:left; color: var(--accent); font-size: 10px; }
        td { padding:12px 10px; background: rgba(255,255,255,0.03); border-radius: 10px; }
        .risk-badge { background: var(--danger); color: white; padding: 2px 6px; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <div id="tooltip"></div>
    <div id="welcome" class="page active">
        <div class="card">
            <h1 style="color:var(--accent); font-size:52px; margin:0;">Team Quasar</h1>
            <h3 style="color:#888;">Money Muling & Forensic Intelligence Engine</h3>
            <button onclick="showDash()">Enter Command Center</button>
        </div>
    </div>
    <div id="dashboard" class="page">
        <div class="app-container">
            <div class="sidebar">
                <h2 style="color:var(--accent);">🛡️ Risk Intelligence</h2>
                <input type="file" id="csvFile" accept=".csv" style="font-size:12px; margin-bottom:15px;">
                <button id="runBtn" onclick="runAnalysis()">Execute Analysis</button>
                <div id="sum" style="font-size:12px; padding:15px; background:rgba(0,242,254,0.05); border-radius:12px; margin:15px 0;"></div>
                <table id="ringTable">
                    <thead><tr><th>Ring ID</th><th>Risk</th><th>Accounts</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
            <div id="cy"></div>
        </div>
    </div>
    <script>
        function showDash() { document.getElementById('welcome').classList.remove('active'); setTimeout(() => document.getElementById('dashboard').classList.add('active'), 300); }
        async function runAnalysis() {
            const file = document.getElementById('csvFile').files[0];
            if(!file) return alert("Select CSV");
            const fd = new FormData(); fd.append("file", file);
            try {
                const res = await fetch('/upload', {method:'POST', body:fd});
                const data = await res.json();
                document.getElementById('sum').innerHTML = `<b>Syndicates:</b> ${data.summary.syndicates} | <b>Flagged:</b> ${data.summary.flagged}`;
                document.getElementById('ringTable').querySelector('tbody').innerHTML = data.fraud_rings.map(r => 
                    `<tr><td><b>${r.ring_id}</b></td><td><span class="risk-badge">${r.risk_score}%</span></td><td>${r.member_accounts.join(', ')}</td></tr>`
                ).join('');
                renderGraph(data.graph_data);
            } catch(e) { alert("Error: " + e.message); }
        }
        function renderGraph(els) {
            const cy = cytoscape({
                container: document.getElementById('cy'),
                elements: els,
                style: [
                    { selector: 'node', style: { 'label':'data(id)', 'color':'#fff', 'font-size':'10px', 'background-color': 'data(comm_color)', 'width': 30, 'height': 30, 'text-valign': 'center', 'border-width': e => e.data('is_suspicious') ? 3 : 0, 'border-color': '#fff' }},
                    { selector: 'edge', style: { 'width':2, 'line-color':'#444', 'target-arrow-shape':'triangle', 'curve-style':'bezier', 'opacity': 0.6 }}
                ],
                layout: { name: 'cose', padding: 50 }
            });
            const tt = document.getElementById('tooltip');
            cy.on('mouseover', 'node', e => {
                const d = e.target.data();
                const riskColor = d.score > 70 ? 'var(--danger)' : '#7cfc00';
                tt.style.display = 'block';
                tt.innerHTML = `<b style="color:var(--accent); font-size:14px;">${d.id}</b><hr style="border:0; border-top:1px solid #333; margin:8px 0;">
                    <b>Status:</b> ${d.pattern}<br>
                    <b>Risk Score:</b> <span style="color:${riskColor}">${d.score.toFixed(1)}%</span><br>
                    <b>Ring:</b> ${d.ring}<br>${d.linked_members ? '<b>Syndicate:</b> ' + d.linked_members : ''}`;
            });
            cy.on('mousemove', 'node', e => { tt.style.top = (e.renderedPosition.y + 15) + 'px'; tt.style.left = (e.renderedPosition.x + 15) + 'px'; });
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