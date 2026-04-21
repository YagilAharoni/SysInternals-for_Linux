#!/usr/bin/env python3
"""LPBA offline analysis and CSV/JSON report generation using pandas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze LPBA JSONL output")
    parser.add_argument("--events", type=str, required=True, help="Path to events.jsonl")
    parser.add_argument("--out", type=str, default="artifacts", help="Report output directory")
    return parser.parse_args()


def load_events(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> int:
    args = parse_args()
    events_path = Path(args.events)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_events(events_path)
    if not rows:
        raise SystemExit("No events to analyze")

    df = pd.DataFrame(rows)
    df.to_csv(out_dir / "lpba_events.csv", index=False)

    risk_summary = (
        df.groupby(["pid", "process_name"], as_index=False)["cumulative_risk"]
        .max()
        .sort_values("cumulative_risk", ascending=False)
    )
    risk_summary.to_csv(out_dir / "lpba_risk_summary.csv", index=False)

    rule_df = (
        df.explode("rule_hits")
        .dropna(subset=["rule_hits"])
        .groupby("rule_hits", as_index=False)
        .size()
        .sort_values("size", ascending=False)
    )
    rule_df.to_csv(out_dir / "lpba_rule_hits.csv", index=False)

    report = {
        "total_events": int(len(df)),
        "unique_processes": int(df["pid"].nunique()),
        "max_risk": int(df["cumulative_risk"].max()),
        "top_process": risk_summary.head(1).to_dict(orient="records"),
    }
    (out_dir / "lpba_analysis_summary.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8"
    )

    print("Generated reports:")
    print(f"- {out_dir / 'lpba_events.csv'}")
    print(f"- {out_dir / 'lpba_risk_summary.csv'}")
    print(f"- {out_dir / 'lpba_rule_hits.csv'}")
    print(f"- {out_dir / 'lpba_analysis_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
