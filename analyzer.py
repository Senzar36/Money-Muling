import networkx as nx
import pandas as pd
import time

class MuleAnalyzer:
    def __init__(self):
        self.risk_weights = {"cycle": 98.0, "smurfing": 85.0, "layering": 75.0, "standard": 15.0}

    def process_data(self, df):
        start_time = time.time()
        G = nx.DiGraph()
        
        # Load all RIFT mandatory columns
        for _, row in df.iterrows():
            G.add_edge(str(row['sender_id']), str(row['receiver_id']), 
                       amount=float(row['amount']),
                       tx_id=str(row['transaction_id']),
                       ts=str(row['timestamp']))
        
        suspicious_accounts = {}
        fraud_rings = []

        # Logic 1: Circular Routing (Cycles 3-5)
        try:
            cycles = list(nx.simple_cycles(G))
            for idx, ring in enumerate(cycles):
                if 3 <= len(ring) <= 5:
                    ring_id = f"RING_{idx+1:03}"
                    fraud_rings.append({
                        "ring_id": ring_id, "pattern": "Circular Routing",
                        "members": [str(n) for n in ring], "score": 98.0
                    })
                    for acc in ring:
                        suspicious_accounts[str(acc)] = {
                            "account_id": str(acc), "score": 98.0, "pattern": "Circular Laundering",
                            "ring": ring_id, "math": f"Cycle detected (L:{len(ring)})"
                        }
        except: pass

        # Logic 2: Smurfing & Layering
        for node in G.nodes():
            n_str = str(node)
            if n_str in suspicious_accounts: continue
            
            in_d, out_d = G.in_degree(node), G.out_degree(node)
            if in_d >= 10 or out_d >= 10:
                suspicious_accounts[n_str] = {
                    "account_id": n_str, "score": 85.0, "pattern": "Smurfing Hub",
                    "ring": "N/A", "math": "Degree Centrality ≥ 10"
                }
            elif (in_d >= 1 and out_d >= 1) and (in_d + out_d <= 4):
                suspicious_accounts[n_str] = {
                    "account_id": n_str, "score": 75.0, "pattern": "Layering Shell",
                    "ring": "N/A", "math": "Intermediate Flow Node"
                }

        return {
            "suspicious_accounts": list(suspicious_accounts.values()),
            "fraud_rings": fraud_rings,
            "summary": {
                "total_nodes": G.number_of_nodes(),
                "flagged_count": len(suspicious_accounts),
                "execution_time": round(time.time() - start_time, 4)
            },
            "graph_elements": self.build_viz(G, suspicious_accounts)
        }

    def build_viz(self, G, susp_map):
        elements = []
        for n in G.nodes():
            info = susp_map.get(str(n), {"score": 15.0, "pattern": "Normal", "ring": "N/A", "math": "Baseline"})
            color = "#ff4d4d" if info['score'] > 90 else "#ffcc00" if info['score'] > 50 else "#7cfc00"
            elements.append({'data': {
                'id': str(n), 'label': str(n), 'color': color, 
                'score': info['score'], 'pattern': info['pattern'], 
                'ring': info['ring'], 'math': info['math']
            }})
        for u, v, d in G.edges(data=True):
            elements.append({'data': {'source': str(u), 'target': str(v), 'amount': d['amount']}})
        return elements