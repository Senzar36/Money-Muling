# Money Muling Detection Challenge | Team Quasar
**RIFT 2026 Hackathon - Graph Theory Track**

## Problem Statement
Traditional database queries fail to detect sophisticated multi-hop muling networks. Team Quasar's engine uses Graph Theory to identify circular fund routing and smurfing hubs in real-time.

## Tech Stack
- **Backend:** Python (FastAPI)
- **Graph Engine:** NetworkX
- **Database:** MySQL
- **Visualization:** Cytoscape.js

## Suspicion Score Methodology
- **Circular Routing (90-100%):** Accounts found in a closed directed cycle (length 3-5) are flagged with the highest risk.
- **High Centrality (70-85%):** Accounts acting as "hubs" (high degree centrality) are flagged for Smurfing/Layering patterns.
- **Pattern Weights:** Scores are calculated based on the account's position within the network and the density of the identified fraud ring.

## Algorithm Approach & Complexity
- **Cycle Detection:** Tarjan’s SCC algorithm - $O(V + E)$
- **Centrality Analysis:** Degree Centrality - $O(E)$
- **Execution:** Optimized for sub-second processing of large transaction CSVs.

## Installation & Setup
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Configure MySQL in `database.py`.
4. Run the app: `python main.py`
5. Access the dashboard at `http://127.0.0.1:8000`

## Team Members
- Anirudh Dhamodaran 
- Jithesh Sankarganesh
- Chris Johnson
- Darshan E