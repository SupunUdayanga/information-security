"""Plotting utilities for avalanche and BIC results.

Owner: M3
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class PlotPaths:
    """Output paths for plots."""

    avalanche_plot: str
    bic_plot: str


def plot_avalanche_bic(output_dir: str) -> PlotPaths:
    """Generate plots for avalanche and BIC experiments."""
    raise NotImplementedError("Implement plot generation.")
