"""Plotting utilities for avalanche and BIC results.

Reads the JSON output files produced by avalanche_test.py and bic_test.py
and generates publication-quality matplotlib charts saved as PNG files.

Generated plots
---------------
1. avalanche_comparison.png  – Bar chart comparing mean ± std for both variants
2. bic_bitprob_heatmap.png   – Per-output-bit flip probability for both variants
3. bic_score_comparison.png  – BIC score comparison bar chart

Owner: M3
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import matplotlib
matplotlib.use('Agg')  # non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlotPaths:
    """Output paths for plots."""

    avalanche_plot: str
    bic_plot: str
    bic_heatmap: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COLORS = {
    'original': '#4C72B0',   # muted blue
    'modified': '#DD8452',   # warm orange
    'ideal':    '#55A868',   # muted green
}

_FONT_TITLE  = {'fontsize': 14, 'fontweight': 'bold'}
_FONT_LABEL  = {'fontsize': 12}
_FONT_TICK   = {'fontsize': 10}


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _setup_fig(figsize=(9, 5)):
    fig, ax = plt.subplots(figsize=figsize)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    return fig, ax


# ---------------------------------------------------------------------------
# Individual plot functions
# ---------------------------------------------------------------------------

def _plot_avalanche_comparison(data: dict, out_path: str) -> None:
    """Bar chart: mean avalanche ratio ± std for original vs modified."""
    orig = data['original']
    mod  = data['modified']

    labels = ['Original SHA-512', 'Modified SHA-512\n(key-dependent)']
    means  = [orig['mean'], mod['mean']]
    stds   = [orig['std'],  mod['std']]
    colors = [_COLORS['original'], _COLORS['modified']]

    fig, ax = _setup_fig(figsize=(8, 5))
    x = np.arange(len(labels))
    bars = ax.bar(x, means, yerr=stds, width=0.45,
                  color=colors, capsize=8, edgecolor='white',
                  linewidth=0.8, error_kw={'elinewidth': 2, 'ecolor': '#333'})

    # Ideal line
    ax.axhline(0.5, color=_COLORS['ideal'], linestyle='--', linewidth=1.5,
               label='Ideal (50%)')

    # Value labels
    for bar, mean, std in zip(bars, means, stds):
        ax.text(bar.get_x() + bar.get_width() / 2,
                mean + std + 0.003,
                f'{mean:.4f}\n±{std:.4f}',
                ha='center', va='bottom', fontsize=10)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, **_FONT_TICK)
    ax.set_ylim(0.40, 0.58)
    ax.set_ylabel('Avalanche Ratio  (bits changed / 512)', **_FONT_LABEL)
    ax.set_title('Avalanche Effect: Original vs Key-Dependent SHA-512', **_FONT_TITLE)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def _plot_bic_score_comparison(data: dict, out_path: str) -> None:
    """Bar chart: BIC score for original vs modified."""
    labels = ['Original SHA-512', 'Modified SHA-512\n(key-dependent)']
    scores = [data['original']['bic_score'] * 100,
              data['modified']['bic_score'] * 100]
    colors = [_COLORS['original'], _COLORS['modified']]

    fig, ax = _setup_fig(figsize=(8, 5))
    x = np.arange(len(labels))
    bars = ax.bar(x, scores, width=0.45, color=colors,
                  edgecolor='white', linewidth=0.8)

    ax.axhline(95, color=_COLORS['ideal'], linestyle='--', linewidth=1.5,
               label='Target (95%)')

    for bar, score in zip(bars, scores):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.5,
                f'{score:.2f}%',
                ha='center', va='bottom', fontsize=11, fontweight='bold')

    ax.set_xticks(x)
    ax.set_xticklabels(labels, **_FONT_TICK)
    ax.set_ylim(0, 115)
    ax.set_ylabel('BIC Score  (% of output bits in [0.45, 0.55])', **_FONT_LABEL)
    ax.set_title('Bit Independence Criterion: Original vs Key-Dependent SHA-512', **_FONT_TITLE)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Saved: {out_path}")


def _plot_bic_heatmap(data: dict, out_path: str) -> None:
    """Per-output-bit flip probability heatmap (512 bits, both variants)."""
    orig_probs = np.array(data['original']['per_bit_probs'])
    mod_probs  = np.array(data['modified']['per_bit_probs'])

    # Reshape to 32×16 grids
    rows, cols = 32, 16
    orig_grid = orig_probs.reshape(rows, cols)
    mod_grid  = mod_probs.reshape(rows, cols)

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    for ax, grid, title in zip(
        axes,
        [orig_grid, mod_grid],
        ['Original SHA-512', 'Modified SHA-512 (key-dependent)'],
    ):
        im = ax.imshow(grid, vmin=0.35, vmax=0.65, cmap='RdYlGn', aspect='auto')
        ax.set_title(title, **_FONT_TITLE)
        ax.set_xlabel('Output bit group (0–15)', **_FONT_LABEL)
        ax.set_ylabel('Output bit group (0–31)', **_FONT_LABEL)
        fig.colorbar(im, ax=ax, label='Flip probability', fraction=0.046, pad=0.04)

    fig.suptitle('BIC: Per-Output-Bit Flip Probability Heatmap\n(green ≈ ideal 0.5)',
                 **_FONT_TITLE, y=1.02)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  Saved: {out_path}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def plot_avalanche_bic(output_dir: str) -> PlotPaths:
    """Generate plots for avalanche and BIC experiments.

    Parameters
    ----------
    output_dir:
        Directory where PNG files will be written.  Also expects
        ``<project_root>/results/avalanche_results.json`` and
        ``<project_root>/results/bic_results.json`` to exist.

    Returns
    -------
    PlotPaths
        Absolute paths of the generated plot files.
    """
    os.makedirs(output_dir, exist_ok=True)
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'results')

    # ── Avalanche ──────────────────────────────────────────────────────────
    avalanche_json = os.path.join(results_dir, 'avalanche_results.json')
    avalanche_plot = os.path.join(output_dir, 'avalanche_comparison.png')
    if os.path.exists(avalanche_json):
        data = _load_json(avalanche_json)
        _plot_avalanche_comparison(data, avalanche_plot)
    else:
        print(f"  [WARN] Missing {avalanche_json} – skipping avalanche plot.")
        avalanche_plot = ''

    # ── BIC ───────────────────────────────────────────────────────────────
    bic_json  = os.path.join(results_dir, 'bic_results.json')
    bic_plot  = os.path.join(output_dir, 'bic_score_comparison.png')
    bic_hmap  = os.path.join(output_dir, 'bic_bitprob_heatmap.png')
    if os.path.exists(bic_json):
        data = _load_json(bic_json)
        _plot_bic_score_comparison(data, bic_plot)
        if 'per_bit_probs' in data.get('original', {}):
            _plot_bic_heatmap(data, bic_hmap)
        else:
            bic_hmap = ''
    else:
        print(f"  [WARN] Missing {bic_json} – skipping BIC plots.")
        bic_plot = ''
        bic_hmap = ''

    return PlotPaths(
        avalanche_plot=avalanche_plot,
        bic_plot=bic_plot,
        bic_heatmap=bic_hmap,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    project_root = os.path.join(os.path.dirname(__file__), '..')
    out_dir = os.path.join(project_root, 'results', 'plots')
    print(f"Generating avalanche & BIC plots → {out_dir}")
    paths = plot_avalanche_bic(out_dir)
    print("\nDone.")
    if paths.avalanche_plot:
        print(f"  Avalanche plot : {paths.avalanche_plot}")
    if paths.bic_plot:
        print(f"  BIC score plot : {paths.bic_plot}")
    if paths.bic_heatmap:
        print(f"  BIC heatmap    : {paths.bic_heatmap}")
