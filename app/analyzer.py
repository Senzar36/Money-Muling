import time

import networkx as nx
import pandas as pd


class MuleAnalyzer:
    """Detect suspicious transaction structures in a directed account graph."""

    RISK_WEIGHTS = {
        "cycle": 98.5,
        "smurfing": 85.0,
        "layering": 65.0,
        "normal": 10.0,
    }

    def process_data(self, df: pd.DataFrame) -> dict:
        start_time = time.perf_counter()
        df = self._clean_data(df)
        graph = self._build_graph(df)

        suspicious_accounts = {}
        fraud_rings = self._detect_cycles(graph, suspicious_accounts)
        self._detect_hubs_and_layering(graph, suspicious_accounts)

        full_registry = self._build_registry(graph, suspicious_accounts)

        return {
            "suspicious_accounts": list(suspicious_accounts.values()),
            "full_registry": full_registry,
            "fraud_rings": fraud_rings,
            "summary": {
                "total_nodes": graph.number_of_nodes(),
                "total_edges": graph.number_of_edges(),
                "execution_time": round(time.perf_counter() - start_time, 4),
            },
            "graph_elements": self._build_visualization(graph, suspicious_accounts),
        }

    @staticmethod
    def _clean_data(df: pd.DataFrame) -> pd.DataFrame:
        cleaned = df.copy()
        cleaned.columns = [str(column).strip().lower() for column in cleaned.columns]

        required = {"sender_id", "receiver_id", "amount"}
        missing = required - set(cleaned.columns)
        if missing:
            raise ValueError(
                "Missing required columns: " + ", ".join(sorted(missing))
            )

        for column in cleaned.columns:
            if cleaned[column].dtype == object:
                cleaned[column] = cleaned[column].astype(str).str.strip()

        cleaned["amount"] = pd.to_numeric(
            cleaned["amount"], errors="coerce"
        ).fillna(0)

        return cleaned

    @staticmethod
    def _build_graph(df: pd.DataFrame) -> nx.DiGraph:
        graph = nx.DiGraph()

        for row in df.itertuples(index=False):
            sender = str(row.sender_id).strip()
            receiver = str(row.receiver_id).strip()
            graph.add_edge(sender, receiver, amount=float(row.amount))

        return graph

    def _detect_cycles(self, graph: nx.DiGraph, suspicious_accounts: dict) -> list:
        fraud_rings = []

        # NetworkX simple_cycles enumerates directed cycles directly.
        try:
            cycles = nx.simple_cycles(graph)
            for index, ring in enumerate(cycles, start=1):
                if 3 <= len(ring) <= 5:
                    ring_id = f"RING_{index:03}"
                    fraud_rings.append(
                        {
                            "ring_id": ring_id,
                            "pattern": "Circular Laundering",
                            "members": [str(node) for node in ring],
                            "score": self.RISK_WEIGHTS["cycle"],
                        }
                    )

                    for account in ring:
                        account_id = str(account)
                        suspicious_accounts[account_id] = {
                            "account_id": account_id,
                            "score": self.RISK_WEIGHTS["cycle"],
                            "pattern": "Cycle Participant",
                            "math": f"Detected in {len(ring)}-node loop",
                        }
        except nx.NetworkXError:
            return fraud_rings

        return fraud_rings

    def _detect_hubs_and_layering(
        self, graph: nx.DiGraph, suspicious_accounts: dict
    ) -> None:
        for node in graph.nodes:
            account_id = str(node)

            if account_id in suspicious_accounts:
                continue

            in_degree = graph.in_degree(node)
            out_degree = graph.out_degree(node)

            if in_degree >= 8:
                suspicious_accounts[account_id] = {
                    "account_id": account_id,
                    "score": self.RISK_WEIGHTS["smurfing"],
                    "pattern": "Smurfing Hub",
                    "math": f"High in-degree: {in_degree} incoming transactions",
                }
            elif (
                in_degree >= 1
                and out_degree >= 1
                and in_degree + out_degree <= 3
            ):
                suspicious_accounts[account_id] = {
                    "account_id": account_id,
                    "score": self.RISK_WEIGHTS["layering"],
                    "pattern": "Layering Node",
                    "math": "Low-volume pass-through behavior",
                }

    def _build_registry(self, graph, suspicious_accounts) -> dict:
        registry = {}

        for node in graph.nodes:
            account_id = str(node)

            if account_id in suspicious_accounts:
                registry[account_id] = suspicious_accounts[account_id]
            else:
                registry[account_id] = {
                    "account_id": account_id,
                    "score": self.RISK_WEIGHTS["normal"],
                    "pattern": "Normal / Baseline",
                    "math": "No structural anomalies detected",
                }

        return registry

    @staticmethod
    def _build_visualization(graph, suspicious_accounts) -> list:
        elements = []

        for node in graph.nodes:
            account_id = str(node)
            info = suspicious_accounts.get(
                account_id,
                {"score": 10.0, "pattern": "Normal / Baseline"},
            )

            if info["score"] > 90:
                status = "high-risk"
            elif info["score"] > 50:
                status = "medium-risk"
            else:
                status = "normal"

            elements.append(
                {
                    "data": {
                        "id": account_id,
                        "score": info["score"],
                        "pattern": info["pattern"],
                        "status": status,
                    }
                }
            )

        for source, target in graph.edges:
            elements.append(
                {
                    "data": {
                        "id": f"{source}->{target}",
                        "source": str(source),
                        "target": str(target),
                    }
                }
            )

        return elements
