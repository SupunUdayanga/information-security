"""Plotting utilities for speed and collision results.

Reads the JSON output files produced by benchmark.py and partial_collision.py
and generates publication-quality matplotlib charts.

Generated plots
---------------
1. speed_throughput.png      – Throughput vs message size (both variants)
2. speed_overhead.png        – Overhead percentage vs message size
3. collision_attempts.png    – Mean collision attempts (both variants, grouped by config)
4. collision_ratio.png       – Ratio (modified / original) of collision attempts

Owner: M4
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlotPaths:
    """Output paths for plots."""

    speed_plot: str
    collision_plot: str


# ---------------------------------------------------------------------------
# Styling helpers
# ---------------------------------------------------------------------------

_COLORS = {
    'original': '#4C72B0',
    'modified': '#DD8452',
    'overhead': '#C44E52',
    'ratio':    '#8172B2',
    'ideal':    '#55A868',
}

_FONT_TITLE = {'fontsize': 14, 'fontweight': 'bold'}
_FONT_LABEL = {'fontsize': 12}
_FONT_TICK  = {'fontsize': 10}


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _setup_fig(figsize=(9, 5)):
    fig, ax = plt.subplots(figsize=figsize)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    return fig, ax


def _human_size(n: int) -> str:
    for unit in ['B', 'KB', 'MB']:
        if n < 1024:
            return f'{n}{unit}'
        n //= 1024
    return f'{n}MB'


# ---------------------------------------------------------------------------
# Individual plot functions
# ---------------------------------------------------------------------------

def _plot_speed_throughput(data: dict, out_path: str) -> None:
    """Line chart: throughput in KB/s vs message size."""
    sizes = data['sizes']
    orig  = [v / 1024 for v in data['original_bps']]
    mod   = [v / 1024 for v in data['modified_bps']]
    labels = [_human_size(s) for s in sizes]

    fig, ax = _setup_fig(figsize=(9, 5))
    ax.plot(labels, orig, 'o-', color=_COLORS['original'], linewidth=2.2,
            markersize=7, label='Original SHA-512')
    ax.plot(labels, mod,  's--', color=_COLORS['modified'], linewidth=2.2,
            markersize=7, label='Modified SHA-512 (key-dep)')

    ax.set_xlabel('Message Size', **_FONT_LABEL)
    ax.set_ylabel('Throughput  (KB / s)', **_FONT_LABEL)
    ax.set_title('Hashing Speed: Original vs Key-Dependent SHA-512', **_FONT_TITLE)
    ax.legend(fontsize=10)
    ax.tick_params(labelsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def _plot_speed_overhead(data: dict, out_path: str) -> None:
    """Bar chart: percentage overhead of modified variant."""
    sizes    = data['sizes']
    overhead = data['overhead_pct']
    labels   = [_human_size(s) for s in sizes]

    fig, ax = _setup_fig(figsize=(9, 5))
    colors = [_COLORS['overhead'] if v > 10 else _COLORS['ideal'] for v in overhead]
    bars = ax.bar(labels, overhead, color=colors, edgecolor='white', linewidth=0.8)

    ax.axhline(10, color='#333', linestyle='--', linewidth=1.5,
               label='10% target threshold')

    for bar, val in zip(bars, overhead):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.3,
                f'{val:+.2f}%',
                ha='center', va='bottom', fontsize=10)

    ax.set_xlabel('Message Size', **_FONT_LABEL)
    ax.set_ylabel('Overhead  (%)', **_FONT_LABEL)
    ax.set_title('Computational Overhead: Modified vs Original SHA-512', **_FONT_TITLE)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def _plot_collision_attempts(data: dict, out_path: str) -> None:
    """Grouped bar chart: mean collision attempts per (rounds, bits) config."""
    configs = [tuple(c) for c in data['configs']]
    orig_attempts = [data['original_mean_attempts'][str(k)] for k in configs]
    mod_attempts  = [data['modified_mean_attempts'][str(k)] for k in configs]
    labels = [f'r={r}, b={b}' for r, b in configs]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = _setup_fig(figsize=(10, 5))
    bars1 = ax.bar(x - width / 2, orig_attempts, width, label='Original SHA-512',
                   color=_COLORS['original'], edgecolor='white')
    bars2 = ax.bar(x + width / 2, mod_attempts, width, label='Modified SHA-512',
                   color=_COLORS['modified'], edgecolor='white')

    ax.set_xticks(x)
    ax.set_xticklabels(labels, **_FONT_TICK)
    ax.set_xlabel('Configuration  (rounds, target bits)', **_FONT_LABEL)
    ax.set_ylabel('Mean Attempts to Find Partial Collision', **_FONT_LABEL)
    ax.set_title('Partial Collision Resistance: Mean Attempts', **_FONT_TITLE)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def _plot_collision_ratio(data: dict, out_path: str) -> None:
    """Bar chart: ratio of modified / original collision attempts."""
    configs = [tuple(c) for c in data['configs']]
    ratios  = [data['ratios'][str(k)] for k in configs]
    labels  = [f'r={r}, b={b}' for r, b in configs]

    colors = [_COLORS['ideal'] if r >= 1.0 else _COLORS['overhead'] for r in ratios]

    fig, ax = _setup_fig(figsize=(8, 5))
    bars = ax.bar(labels, ratios, color=colors, edgecolor='white', linewidth=0.8)
    ax.axhline(1.0, color='#333', linestyle='--', linewidth=1.5,
               label='Ratio = 1.0  (no change)')

    for bar, r in zip(bars, ratios):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.01,
                f'{r:.3f}×',
                ha='center', va='bottom', fontsize=10)

    ax.set_xlabel('Configuration  (rounds, target bits)', **_FONT_LABEL)
    ax.set_ylabel('Ratio  (modified / original attempts)', **_FONT_LABEL)
    ax.set_title('Collision Resistance Ratio  (>1 = better)', **_FONT_TITLE)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def plot_speed_collision(output_dir: str) -> PlotPaths:
    """Generate plots for speed and collision experiments.

    Parameters
    ----------
    output_dir:
        Directory where PNG files will be written.

    Returns
    -------
    PlotPaths
        Paths to the primary speed and collision plots.
    """
    os.makedirs(output_dir, exist_ok=True)
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'results')

    # ── Speed ─────────────────────────────────────────────────────────────
    bench_json    = os.path.join(results_dir, 'benchmark_results.json')
    speed_plot    = os.path.join(output_dir, 'speed_throughput.png')
    overhead_plot = os.path.join(output_dir, 'speed_overhead.png')

    if os.path.exists(bench_json):
        data = _load_json(bench_json)
        _plot_speed_throughput(data, speed_plot)
        _plot_speed_overhead(data, overhead_plot)
    else:
        print(f"  [WARN] Missing {bench_json} – skipping speed plots.")
        speed_plot = ''

    # ── Collision ─────────────────────────────────────────────────────────
    coll_json   = os.path.join(results_dir, 'collision_results.json')
    coll_plot   = os.path.join(output_dir, 'collision_attempts.png')
    ratio_plot  = os.path.join(output_dir, 'collision_ratio.png')

    if os.path.exists(coll_json):
        data = _load_json(coll_json)
        _plot_collision_attempts(data, coll_plot)
        _plot_collision_ratio(data, ratio_plot)
    else:
        print(f"  [WARN] Missing {coll_json} – skipping collision plots.")
        coll_plot = ''

    return PlotPaths(speed_plot=speed_plot, collision_plot=coll_plot)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    project_root = os.path.join(os.path.dirname(__file__), '..')
    out_dir = os.path.join(project_root, 'results', 'plots')
    print(f"Generating speed & collision plots → {out_dir}")
    paths = plot_speed_collision(out_dir)
    print("\nDone.")
    if paths.speed_plot:
        print(f"  Speed plot      : {paths.speed_plot}")
    if paths.collision_plot:
        print(f"  Collision plot  : {paths.collision_plot}")
