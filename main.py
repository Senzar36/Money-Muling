# main.py
from fastapi import FastAPI, UploadFile, File
import pandas as pd
import networkx as nx
from pydantic import BaseModel
from typing import List

app = FastAPI()

class MuleRing(BaseModel):
    ring_id: str
    members: List[str]
    total_volume: float
    suspicion_score: int

@app.post("/analyze", response_model=List[MuleRing])
async def analyze_transactions(file: UploadFile = File(...)):
    # 1. Error-free CSV reading
    df = pd.read_csv(file.file)
    
    # 2. Build Directed Graph
    G = nx.from_pandas_edgelist(df, 'sender_id', 'receiver_id', 
                                edge_attr='amount', create_using=nx.DiGraph())
    
    # 3. Detect Simple Cycles (Circular Routing)
    rings = []
    cycles = list(nx.simple_cycles(G))
    
    for i, cycle in enumerate(cycles):
        if 3 <= len(cycle) <= 6:  # Common mule ring sizes
            # Calculate total volume flowing through this ring
            edges = zip(cycle, cycle[1:] + [cycle[0]])
            vol = sum([G[u][v]['amount'] for u, v in edges])
            
            rings.append(MuleRing(
                ring_id=f"RING_{i}",
                members=cycle,
                total_volume=vol,
                suspicion_score=min(100, int(vol / 100)) # Simple logic example
            ))
            
    return rings