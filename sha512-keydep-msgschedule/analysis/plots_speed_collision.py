"""Plotting utilities for speed and collision results.

Owner: M4
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlotPaths:
    """Output paths for plots."""

    speed_plot: str
    collision_plot: str


def plot_speed_collision(output_dir: str) -> PlotPaths:
    """Generate plots for speed and collision experiments."""
    raise NotImplementedError("Implement plot generation.")
