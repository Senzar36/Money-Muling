import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from analyzer import MuleAnalyzer
from database import init_db
import pandas as pd
from io import BytesIO

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
engine = MuleAnalyzer()

@app.on_event("startup")
async def startup(): init_db()

HTML_CONTENT = r"""
<!DOCTYPE html>
<html>
<head>
    <title>Quasar | RIFT 2026</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.23.0/cytoscape.min.js"></script>
    <style>
        :root { --accent: #00f2fe; --bg: #0b0e14; }
        body { margin:0; font-family: "Segoe UI", sans-serif; background: var(--bg); color:white; overflow:hidden; }
        .page { position: absolute; width:100%; height:100vh; display:flex; justify-content:center; align-items:center; opacity:0; visibility:hidden; transition:0.5s; }
        .active { opacity:1; visibility:visible; }
        .card { text-align:center; width: 680px; padding:40px; background:rgba(255,255,255,0.05); border-radius:40px; border:1px solid rgba(0,242,254,0.2); backdrop-filter:blur(20px); }
        .app-container { width:98%; height:94%; display:grid; grid-template-columns:450px 1fr; gap:20px; padding:20px; }
        .sidebar { background:rgba(255,255,255,0.05); padding:25px; border-radius:25px; overflow-y:auto; border:1px solid rgba(255,255,255,0.1); }
        #cy { background:rgba(0,0,0,0.3); border-radius:25px; position:relative; }
        button { background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%); border:none; padding:15px; color:#000; border-radius:12px; cursor:pointer; font-weight:800; width:100%; margin:10px 0; text-transform: uppercase; }
        #tooltip { position: absolute; display: none; background: rgba(10,10,15,0.98); border: 1px solid var(--accent); padding: 15px; border-radius: 12px; z-index: 1000; pointer-events:none; font-size:12px; }
        table { width:100%; border-collapse:collapse; font-size:11px; margin-top:15px; }
        th, td { border: 1px solid rgba(255,255,255,0.1); padding: 8px; text-align: left; }
    </style>
</head>
<body>
    <div id="tooltip"></div>
    <div id="welcome" class="page active">
        <div class="card">
            <h1>Money Muling Detection Challenge</h1>
            <h2 style="color:var(--accent);">Team Quasar</h2>
            <div style="text-align:left; background:rgba(255,255,255,0.03); padding:25px; border-radius:20px; margin:25px 0;">
                <p><b>What is a Money Mule?</b> An individual used by criminals to transfer illicit funds, facilitating the "layering" stage of money laundering to hide the origin of the money.</p>
                <p><b>Quasar Engine:</b> We use Graph Theory to detect <b>circular laundering</b>, <b>smurfing aggregation</b>, and <b>layering shells</b> that bypass standard rules.</p>
                <ul>
                    <li>Directed Graph Visualization</li>
                    <li>Cycle Detection (Math: v0 -> v1 -> ... -> v0)</li>
                    <li>RIFT-Compliant Forensic Reporting</li>
                </ul>
            </div>
            <button onclick="showDash()">Enter Command Center</button>
        </div>
    </div>
    <div id="dashboard" class="page">
        <div class="app-container">
            <div class="sidebar">
                <h2 style="color:var(--accent); margin-top:0;">🛡️ Forensic Intel</h2>
                <input type="file" id="csvFile" accept=".csv" style="margin-bottom:15px; font-size:12px;">
                <button onclick="runAnalysis()">Execute Scan</button>
                <button id="dlBtn" style="display:none; background:transparent; border:1px solid var(--accent); color:var(--accent);" onclick="downloadReport()">Download Forensic Report</button>
                <div id="summaryText" style="margin:15px 0; font-size:12px; color:var(--accent);"></div>
                <table id="ringTable">
                    <thead><tr><th>Ring ID</th><th>Type</th><th>Score</th><th>Logic</th></tr></thead>
                    <tbody></tbody>
                </table>
            </div>
            <div id="cy"></div>
        </div>
    </div>
    <script>
        let currentReport = null;
        function showDash() { document.getElementById('welcome').classList.remove('active'); document.getElementById('dashboard').classList.add('active'); }
        
        async function runAnalysis() {
            const file = document.getElementById('csvFile').files[0];
            const fd = new FormData(); fd.append("file", file);
            const res = await fetch('/upload', {method:'POST', body:fd});
            currentReport = await res.json();
            
            document.getElementById('dlBtn').style.display = 'block';
            document.getElementById('summaryText').innerText = `Nodes: ${currentReport.summary.total_nodes} | Flagged: ${currentReport.summary.flagged_count} | Time: ${currentReport.summary.execution_time}s`;
            
            const tbody = document.querySelector('#ringTable tbody');
            tbody.innerHTML = currentReport.fraud_rings.map(r => `<tr><td>${r.ring_id}</td><td>${r.pattern}</td><td>${r.score}%</td><td>Graph Cycle</td></tr>`).join('');
            
            renderGraph(currentReport.graph_elements);
        }

        function downloadReport() {
            const blob = new Blob([JSON.stringify(currentReport, null, 2)], {type: 'application/json'});
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'Forensic_Report_Quasar.json';
            a.click();
        }

        function renderGraph(els) {
            const cy = cytoscape({
                container: document.getElementById('cy'),
                elements: els,
                style: [
                    { selector: 'node', style: { 'label':'data(id)', 'background-color':'data(color)', 'color':'#fff', 'font-size':'10px', 'width':30, 'height':30, 'text-valign':'center', 'text-outline-width':2, 'text-outline-color':'#000' }},
                    { selector: 'edge', style: { 'width':2, 'line-color':'#444', 'target-arrow-shape':'triangle', 'curve-style':'bezier' }}
                ],
                layout: { name: 'cose', padding: 40 }
            });
            const tt = document.getElementById('tooltip');
            cy.on('mouseover', 'node', e => {
                const d = e.target.data();
                tt.style.display = 'block';
                tt.innerHTML = `<b>ACCOUNT: ${d.id}</b><br>Score: ${d.score}%<br>Pattern: ${d.pattern}<br>Ring: ${d.ring}<br>Math: ${d.math}`;
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
        df = pd.read_csv(BytesIO(await file.read()))
        df.columns = [str(c).strip().lower() for c in df.columns]
        return engine.process_data(df)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)