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
        except Exception as e:
            raise ValueError(f"Invalid CSV format: {str(e)}")
        
        required = ['sender_id', 'receiver_id', 'amount', 'timestamp']
        for col in required:
            if col not in df.columns:
                raise ValueError(f"Missing mandatory column: {col}")

        # Build Directed Graph
        G = nx.DiGraph()
        for _, row in df.iterrows():
            G.add_edge(str(row['sender_id']), str(row['receiver_id']), 
                       amount=float(row['amount']), timestamp=str(row['timestamp']))
        
        suspicious_accounts = {}
        fraud_rings = []

        # 1. Circular Routing Detection (Cycles 3-5)
        try:
            cycles = list(nx.simple_cycles(G))
            for idx, ring in enumerate(cycles):
                if 3 <= len(ring) <= 5:
                    ring_id = f"RING_{idx+1:03}"
                    fraud_rings.append({
                        "ring_id": ring_id, 
                        "member_accounts": [str(n) for n in ring], 
                        "pattern_type": "Circular Routing", 
                        "risk_score": 95.0
                    })
                    for acc in ring:
                        suspicious_accounts[str(acc)] = {
                            "score": 95.0, 
                            "pattern": f"Circular Loop ({len(ring)} nodes)", 
                            "ring": ring_id
                        }
        except: pass

        # 2. Smurfing Detection (Degree Centrality / Fan-in/out)
        for node in G.nodes():
            in_deg = G.in_degree(node)
            out_deg = G.out_degree(node)
            if in_deg >= 10 or out_deg >= 10:
                if str(node) not in suspicious_accounts:
                    pattern = "Smurfing Hub (Fan-in)" if in_deg >= 10 else "Smurfing Hub (Fan-out)"
                    suspicious_accounts[str(node)] = {
                        "score": 85.0, 
                        "pattern": pattern, 
                        "ring": "N/A"
                    }

        # Save to Database
        for acc_id, data in suspicious_accounts.items():
            save_mule(acc_id, data["score"], [data["pattern"]], data["ring"])

        # Prepare Graph Elements with Metadata for Hover Intelligence
        cy_elements = []
        for node in G.nodes():
            info = suspicious_accounts.get(str(node), {"score": 0, "pattern": "Normal Activity", "ring": "None"})
            cy_elements.append({
                'data': {
                    'id': str(node), 
                    'label': str(node),
                    'is_suspicious': str(node) in suspicious_accounts,
                    'score': info['score'],
                    'pattern': info['pattern'],
                    'ring': info['ring']
                }
            })
        for u, v, d in G.edges(data=True):
            cy_elements.append({
                'data': {
                    'source': str(u), 
                    'target': str(v), 
                    'amount': d.get('amount', 0)
                }
            })

        return {
            "suspicious_accounts": list(suspicious_accounts.values()),
            "fraud_rings": fraud_rings,
            "summary": {
                "total_accounts_analyzed": int(G.number_of_nodes()),
                "suspicious_accounts_flagged": int(len(suspicious_accounts)),
                "processing_time_seconds": round(time.time() - start_time, 2)
            },
            "graph_data": cy_elements
        }

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

HTML_CONTENT = """
<!DOCTYPE html>
<html>
<head>
    <title>Quasar | RIFT 2026</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.23.0/cytoscape.min.js"></script>
    <style>
        :root { --accent: #00f2fe; --bg: #0f0c29; --danger: #ff4d4d; }
        body { margin:0; font-family: "Comic Sans MS", cursive; background: var(--bg); color:white; overflow:hidden; }
        
        .page { 
            position: absolute; width:100%; height:100vh; 
            display:flex; justify-content:center; align-items:center; 
            opacity:0; visibility:hidden; transition:0.6s ease-in-out; transform:scale(0.95);
        }
        .active { opacity:1; visibility:visible; transform:scale(1); }

        .card { 
            text-align:center; max-width:700px; padding:50px; 
            background:rgba(255,255,255,0.05); border-radius:30px; 
            border:1px solid rgba(255,255,255,0.1); backdrop-filter:blur(15px); 
            box-shadow: 0 20px 50px rgba(0,0,0,0.5); 
        }
        
        .app-container { width:98%; height:90%; display:grid; grid-template-columns:350px 1fr; gap:15px; }
        .sidebar { background:rgba(0,0,0,0.5); padding:20px; border-radius:20px; border:1px solid rgba(255,255,255,0.1); overflow-y:auto; }
        #cy { background:rgba(0,0,0,0.2); border-radius:20px; position:relative; }

        /* FORENSIC TOOLTIP */
        #tooltip { 
            position: absolute; display: none; background: rgba(0,0,0,0.9); 
            border: 1px solid var(--accent); padding: 15px; border-radius: 12px; 
            z-index: 1000; font-size: 12px; pointer-events: none; width: 230px;
            box-shadow: 0 0 20px rgba(0,242,254,0.4); line-height: 1.5;
        }

        button { 
            background:linear-gradient(45deg, #00c6ff, #0072ff); border:none; 
            padding:15px 30px; color:white; border-radius:30px; cursor:pointer; 
            font-family:inherit; font-weight:bold; width:100%; margin:10px 0; transition: 0.3s;
        }
        button:hover { transform: scale(1.03); box-shadow: 0 0 15px var(--accent); }
        
        table { width:100%; border-collapse:collapse; font-size:11px; margin-top:15px; }
        th, td { padding:8px; border:1px solid rgba(255,255,255,0.1); text-align:left; }
        input[type="file"] { color: white; font-size: 12px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div id="tooltip"></div>

    <div id="welcome" class="page active">
        <div class="card">
            <h1 style="color:var(--accent); font-size:45px; margin:0;">Team Quasar</h1>
            <h3 style="opacity:0.8;">Money Muling Forensic Engine</h3>
            <p style="line-height:1.6; margin:25px 0;">
                Our engine identifies illicit fund layering and money muling networks using advanced directed graph algorithms. 
                By analyzing transactional relationships over temporal windows, Team Quasar detects sophisticated fraud 
                patterns that traditional database queries miss.
            </p>
            <button onclick="showDash()">ENTER DASHBOARD</button>
        </div>
    </div>

    <div id="dashboard" class="page">
        <div class="app-container">
            <div class="sidebar">
                <h2 style="color:var(--accent); margin-top:0;">Intelligence</h2>
                <input type="file" id="csvFile" accept=".csv">
                <button id="runBtn" onclick="runAnalysis()">RUN ANALYSIS</button>
                <div id="summaryText" style="font-size:12px; margin:15px 0; color:var(--accent); font-weight:bold;"></div>
                <table id="ringTable">
                    <thead><tr><th>Ring ID</th><th>Pattern</th><th>Risk</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
            <div id="cy"></div>
        </div>
    </div>

    <script>
        function showDash() {
            document.getElementById('welcome').classList.remove('active');
            setTimeout(() => { document.getElementById('dashboard').classList.add('active'); }, 400);
        }

        async function runAnalysis() {
            const file = document.getElementById('csvFile').files[0];
            if(!file) return alert("Please select a CSV file.");
            
            const btn = document.getElementById('runBtn');
            btn.innerText = "PROCESSING...";
            const fd = new FormData(); fd.append("file", file);

            try {
                const res = await fetch('/upload', {method:'POST', body:fd});
                const data = await res.json();
                if(!res.ok) throw new Error(data.detail);

                document.getElementById('summaryText').innerText = `Nodes: ${data.summary.total_accounts_analyzed} | Flagged: ${data.summary.suspicious_accounts_flagged}`;
                
                const tbody = document.getElementById('ringTable').querySelector('tbody');
                tbody.innerHTML = data.fraud_rings.map(r => 
                    `<tr><td>${r.ring_id}</td><td>${r.pattern_type}</td><td>${r.risk_score}%</td></tr>`
                ).join('');

                renderGraph(data.graph_data);
            } catch(e) { alert("Analysis Error: " + e.message); }
            finally { btn.innerText = "RUN ANALYSIS"; }
        }

        function renderGraph(els) {
            const cy = cytoscape({
                container: document.getElementById('cy'),
                elements: els,
                style: [
                    { selector: 'node', style: { 
                        'label':'data(id)', 'color':'#fff', 'font-size':'10px', 'font-family':'inherit',
                        'background-color': e => e.data('is_suspicious') ? '#ff4d4d' : '#00f2fe',
                        'width': e => e.data('is_suspicious') ? 35 : 22,
                        'height': e => e.data('is_suspicious') ? 35 : 22,
                        'text-valign': 'center', 'text-halign': 'center'
                    }},
                    { selector: 'edge', style: { 
                        'width': 2, 'line-color': '#555', 'target-arrow-shape': 'triangle', 
                        'curve-style': 'bezier', 'opacity': 0.7, 'target-arrow-color': '#555' 
                    }}
                ],
                layout: { name: 'cose', padding: 50, animate: true }
            });

            // HOVER INTELLIGENCE LOGIC
            const tooltip = document.getElementById('tooltip');
            
            cy.on('mouseover', 'node', function(evt){
                const d = evt.target.data();
                tooltip.style.display = 'block';
                tooltip.innerHTML = `
                    <div style="border-bottom:1px solid #00f2fe; padding-bottom:5px; margin-bottom:8px;">
                        <b style="color:#00f2fe">FORENSIC DATA</b>
                    </div>
                    <b>ID:</b> ${d.id}<br>
                    <b>Status:</b> ${d.is_suspicious ? '<span style="color:#ff4d4d">Flagged</span>' : 'Clear'}<br>
                    <b>Pattern:</b> ${d.pattern}<br>
                    <b>Risk Score:</b> ${d.score}%<br>
                    <b>Ring Ref:</b> ${d.ring}
                `;
            });

            cy.on('mousemove', 'node', function(evt){
                tooltip.style.top = (evt.renderedPosition.y + 15) + 'px';
                tooltip.style.left = (evt.renderedPosition.x + 15) + 'px';
            });

            cy.on('mouseout', 'node', function(){
                tooltip.style.display = 'none';
            });
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