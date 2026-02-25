import networkx as nx
import pandas as pd
import time

class MuleAnalyzer:
    def __init__(self):
        self.risk_weights = {"cycle": 98.5, "smurfing": 85.0, "layering": 65.0, "normal": 10.0}

    def process_data(self, df):
        start_time = time.time()
        G = nx.DiGraph()
        
        # 1. Clean Column Names
        df.columns = [str(c).strip().lower() for c in df.columns]
        
        # 2. Deep Clean Data Values (Strips hidden tabs and spaces from all cells)
        for col in df.columns:
            if df[col].dtype == object:
                df[col] = df[col].astype(str).str.strip()
            # Ensure numeric columns are cleaned and converted
            if 'amount' in col:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # 3. Build Graph
        for _, row in df.iterrows():
            sender = str(row['sender_id'])
            receiver = str(row['receiver_id'])
            G.add_edge(sender, receiver, amount=float(row['amount']))
        
        suspicious_accounts = {}
        fraud_rings = []

        # 4. Detection Logic: Cycles
        try:
            cycles = list(nx.simple_cycles(G))
            for idx, ring in enumerate(cycles):
                if 3 <= len(ring) <= 5:
                    ring_id = f"CLS_{idx+1:03}"
                    fraud_rings.append({
                        "ring_id": ring_id, 
                        "pattern": "Circular Laundering",
                        "members": [str(n) for n in ring], 
                        "score": self.risk_weights["cycle"]
                    })
                    for acc in ring:
                        suspicious_accounts[str(acc)] = {
                            "account_id": str(acc), 
                            "score": self.risk_weights["cycle"], 
                            "pattern": "Cycle Participant",
                            "math": f"Detected in {len(ring)}-node loop"
                        }
        except: pass

        # 5. Detection Logic: Smurfing/Hubs
        for node in G.nodes():
            n_str = str(node)
            if n_str in suspicious_accounts: continue
            
            in_d = G.in_degree(node)
            out_d = G.out_degree(node)
            
            if in_d >= 8:
                suspicious_accounts[n_str] = {
                    "account_id": n_str, "score": self.risk_weights["smurfing"], 
                    "pattern": "Smurfing Hub",
                    "math": f"High In-Degree: {in_d} incoming trans."
                }
            elif (in_d >= 1 and out_d >= 1) and (in_d + out_d <= 3):
                suspicious_accounts[n_str] = {
                    "account_id": n_str, "score": self.risk_weights["layering"], 
                    "pattern": "Layering Node",
                    "math": "Low-volume pass-through behavior"
                }

        # 6. Full Registry for Entity Search
        full_registry = {}
        for node in G.nodes():
            n_str = str(node)
            if n_str in suspicious_accounts:
                full_registry[n_str] = suspicious_accounts[n_str]
            else:
                full_registry[n_str] = {
                    "account_id": n_str,
                    "score": self.risk_weights["normal"],
                    "pattern": "Normal / Baseline",
                    "math": "No structural anomalies detected"
                }

        return {
            "suspicious_accounts": list(suspicious_accounts.values()),
            "full_registry": full_registry,
            "fraud_rings": fraud_rings,
            "summary": {
                "total_nodes": G.number_of_nodes(),
                "execution_time": round(time.time() - start_time, 4)
            },
            "graph_elements": self.build_viz(G, suspicious_accounts)
        }

    def build_viz(self, G, susp_map):
        elements = []
        for n in G.nodes():
            n_str = str(n)
            info = susp_map.get(n_str, {"score": 10.0, "pattern": "Normal"})
            color = "#ff4d4d" if info['score'] > 90 else "#ffcc00" if info['score'] > 50 else "#10b981"
            elements.append({'data': {'id': n_str, 'color': color, 'score': info['score'], 'pattern': info['pattern']}})
        for u, v in G.edges():
            elements.append({'data': {'source': str(u), 'target': str(v)}})
        return elements