# Quasar

Graph-based money muling detection prototype built during the RIFT 2026 hackathon.

> **Status:** Hackathon prototype / educational project

## Overview

Quasar analyzes financial transaction data as a **directed graph**, where accounts are nodes and transactions are directed edges.

The current prototype looks for a small set of structural patterns:

- **Circular laundering:** directed cycles containing 3–5 accounts.
- **Smurfing hubs:** accounts with at least 8 incoming transactions.
- **Layering nodes:** low-degree pass-through accounts with both incoming and outgoing transactions.

Each flagged account receives a simple rule-based risk score. The dashboard then visualizes the transaction network and allows individual accounts to be searched.

## How it works

```text
CSV transaction data
        |
        v
   Data cleaning
        |
        v
Directed transaction graph
        |
        +--------------------+
        |                    |
        v                    v
 Cycle detection      Degree-based rules
        |                    |
        +---------+----------+
                  |
                  v
          Suspicious accounts
                  |
                  v
       Dashboard + graph view
```

## Tech stack

- **Python**
- **FastAPI**
- **NetworkX**
- **Pandas**
- **SQLite**
- **Cytoscape.js**
- **HTML / CSS / JavaScript**

## Project structure

```text
quasar/
├── app/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── database.py
│   └── main.py
├── data/
│   └── sample_transactions.csv
├── static/
│   ├── app.js
│   └── styles.css
├── templates/
│   └── index.html
├── tests/
├── .gitignore
├── .gitattributes
├── README.md
└── requirements.txt
```

## Getting started

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd quasar
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the application

```bash
python -m uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Input format

The uploaded CSV must contain these columns:

```text
sender_id
receiver_id
amount
```

A sample dataset is included in `data/sample_transactions.csv`.

## API

### `POST /upload`

Uploads a CSV file and returns the analysis results.

### `GET /search?id=<account_id>`

Looks up an account in the most recently analyzed dataset.

FastAPI also provides interactive API documentation at:

```text
http://127.0.0.1:8000/docs
```

## Detection rules

| Pattern | Rule | Score |
|---|---|---:|
| Circular laundering | Account belongs to a 3–5 node directed cycle | 98.5 |
| Smurfing hub | At least 8 incoming transactions | 85.0 |
| Layering node | Has incoming + outgoing transactions and total degree ≤ 3 | 65.0 |
| Baseline | No rule triggered | 10.0 |

These are **heuristic rules for a hackathon prototype**, not a production fraud-detection or financial-compliance system.

## Limitations

- The current detector uses graph-structure heuristics rather than a trained ML model.
- Cycle enumeration can become expensive on larger graphs.
- The current analysis is held in memory for account search.
- SQLite is initialized for future persistence, but flagged results are not currently written to the database.
- Risk scores are rule-based and should not be interpreted as real-world fraud probabilities.
- The project is intended as a prototype and should not be used for real financial investigations.

## Team

- Anirudh Dhamodaran
- Jithesh Sankarganesh
- Chris Johnson
- Darshan E

## License

MIT License
