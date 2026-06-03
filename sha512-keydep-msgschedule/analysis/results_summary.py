"""Aggregate and summarize experiment results.

Owner: M4
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SummaryReport:
    """Summary metadata for experiment outputs."""

    report_path: str


def generate_summary_report(output_dir: str) -> SummaryReport:
    """Generate a summary report from experiment outputs."""
    raise NotImplementedError("Implement summary report generation.")
