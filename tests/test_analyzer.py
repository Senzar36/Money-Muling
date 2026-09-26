from pathlib import Path

import pandas as pd

from app.analyzer import MuleAnalyzer


def test_sample_dataset_contains_expected_columns():
    sample_path = Path(__file__).resolve().parents[1] / "data" / "sample_transactions.csv"
    df = pd.read_csv(sample_path)
    result = MuleAnalyzer().process_data(df)

    assert result["summary"]["total_nodes"] > 0
    assert result["summary"]["total_edges"] > 0
    assert "fraud_rings" in result
