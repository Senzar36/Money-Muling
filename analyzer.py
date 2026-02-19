import pandas as pd
import networkx as nx
from io import BytesIO

class MuleAnalyzer:
    @staticmethod
    def process_csv_with_graph(file_contents):
        df = pd.read_csv(BytesIO(file_contents))
        G = nx.from_pandas_edgelist(df, 'sender_id', 'receiver_id', 
                                    edge_attr='amount', create_using=nx.DiGraph())
        
        # 1. Detect Rings
        rings = list(nx.simple_cycles(G))
        ring_members = {acc for ring in rings for acc in ring}
        
        # 2. Calculate Risk Scores (0 to 100)
        # We use PageRank to see which nodes are "central hubs" for money flow
        pagerank = nx.pagerank(G, weight='amount')
        
        risk_scores = {}
        for node in G.nodes():
            base_score = pagerank.get(node, 0) * 1000 # Scaling pagerank
            if node in ring_members:
                base_score += 50  # Heavy penalty for being in a ring
            
            risk_scores[node] = min(round(base_score, 2), 100) # Cap at 100
        
        # Add risk score to node data for the frontend
        for node in G.nodes():
            G.nodes[node]['risk_score'] = risk_scores[node]

        return rings, risk_scores, G