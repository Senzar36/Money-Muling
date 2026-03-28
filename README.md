# Money Muling Detection Challenge | Team Quasar
**RIFT 2026 Hackathon - Graph Theory Track**

## 🔍 Why this project exists
Money muling is a key technique used in financial fraud, where illicit funds are transferred through multiple accounts to obscure their origin. Traditional database queries fail to detect these complex, multi-hop transaction patterns.

## 🚀 What this system does
This system models financial transactions as a **graph** and detects:
- Circular fund flows (fraud rings)
- High-centrality accounts (potential hubs)
- Suspicious transaction patterns

## 🧠 Key Idea
Instead of analyzing transactions in isolation, this project uses **graph theory** to analyze relationships between accounts.

## ✨ What makes it different
- Uses **Tarjan’s SCC algorithm** for fraud ring detection
- Detects **multi-hop laundering patterns**
- Designed for **large-scale transaction datasets**

## Tech Stack
- **Backend:** Python (FastAPI)
- **Graph Engine:** NetworkX
- **Database:** MySQL
- **Visualization:** Cytoscape.js

## 📊 Example Insight

Input: Transaction dataset (CSV)  
Output:
- Flagged accounts with suspicion scores
- Identified fraud rings
- Visualization of transaction graph

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
