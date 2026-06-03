"""run_all.py — Master experiment runner.

Runs all experiments in order, then generates all plots and the summary report.

Usage
-----
    python run_all.py [--quick]

Options
-------
--quick     Use reduced sample counts for a fast smoke-test (< 2 minutes).
            Default runs the full experiment suite (~10–20 minutes in pure Python).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time

# ---------------------------------------------------------------------------
# Ensure the project root is on the path
# ---------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from experiments.avalanche_test import (
    run_avalanche_tests,
    run_avalanche_tests_original,
)
from experiments.bic_test import run_bic_tests, run_bic_tests_original
from experiments.benchmark import run_benchmark_suite
from experiments.partial_collision import run_collision_suite
from analysis.plots_avalanche_bic import plot_avalanche_bic
from analysis.plots_speed_collision import plot_speed_collision
from analysis.results_summary import generate_summary_report

RESULTS_DIR = os.path.join(ROOT, 'results')
PLOTS_DIR   = os.path.join(RESULTS_DIR, 'plots')

KEY = b'ec6204-miniproject-sha512-keydep'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _save_json(data: dict, filename: str) -> None:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, filename)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  -> Saved: {path}")


def _section(title: str) -> None:
    print(f'\n{"=" * 60}')
    print(f'  {title}')
    print(f'{"=" * 60}')


# ---------------------------------------------------------------------------
# Experiment runners
# ---------------------------------------------------------------------------

def run_avalanche(n_messages: int, msg_len: int, bits_per_msg: int) -> None:
    _section('1 / 4  Avalanche Effect')
    rng = random.Random(42)
    messages = [bytes(rng.randint(0, 255) for _ in range(msg_len))
                for _ in range(n_messages)]

    print(f'  Messages: {n_messages} x {msg_len} bytes, '
          f'{bits_per_msg} bit-flips each -> {n_messages * bits_per_msg} trials')

    t0 = time.perf_counter()
    orig = run_avalanche_tests_original(messages, bits_per_message=bits_per_msg)
    t1 = time.perf_counter()
    mod  = run_avalanche_tests(messages, KEY, bits_per_message=bits_per_msg)
    t2 = time.perf_counter()

    print(f'  Original : mean={orig.bit_flips_mean:.6f} std={orig.bit_flips_std:.6f} '
          f'({t1-t0:.1f}s)')
    print(f'  Modified : mean={mod.bit_flips_mean:.6f}  std={mod.bit_flips_std:.6f} '
          f'({t2-t1:.1f}s)')

    _save_json({
        'original': {
            'mean': orig.bit_flips_mean,
            'std':  orig.bit_flips_std,
            'trials': orig.total_trials,
        },
        'modified': {
            'mean': mod.bit_flips_mean,
            'std':  mod.bit_flips_std,
            'trials': mod.total_trials,
        },
    }, 'avalanche_results.json')


def run_bic(n_messages: int, msg_len: int, bits_per_msg: int) -> None:
    _section('2 / 4  Bit Independence Criterion (BIC)')
    rng = random.Random(7)
    messages = [bytes(rng.randint(0, 255) for _ in range(msg_len))
                for _ in range(n_messages)]

    print(f'  Messages: {n_messages} x {msg_len} bytes, '
          f'{bits_per_msg} bit-flips each -> {n_messages * bits_per_msg} trials')

    t0 = time.perf_counter()
    orig = run_bic_tests_original(messages, bits_to_flip=bits_per_msg)
    t1 = time.perf_counter()
    mod  = run_bic_tests(messages, KEY, bits_to_flip=bits_per_msg)
    t2 = time.perf_counter()

    print(f'  Original : mean={orig.independence_mean:.6f} '
          f'BIC={orig.bic_score*100:.2f}% ({t1-t0:.1f}s)')
    print(f'  Modified : mean={mod.independence_mean:.6f}  '
          f'BIC={mod.bic_score*100:.2f}% ({t2-t1:.1f}s)')

    _save_json({
        'original': {
            'flip_prob_mean': orig.independence_mean,
            'flip_prob_std':  orig.independence_std,
            'bic_score':      orig.bic_score,
            'per_bit_probs':  orig.per_bit_probs,
        },
        'modified': {
            'flip_prob_mean': mod.independence_mean,
            'flip_prob_std':  mod.independence_std,
            'bic_score':      mod.bic_score,
            'per_bit_probs':  mod.per_bit_probs,
        },
    }, 'bic_results.json')


def run_bench(n_timing: int) -> None:
    _section('3 / 4  Hashing Speed Benchmark')
    print(f'  Timing iterations: {n_timing} per size')

    suite = run_benchmark_suite(KEY, n_warmup=5, n_timing=n_timing)

    sizes = sorted(suite.original.keys())
    _save_json({
        'sizes':        sizes,
        'original_bps': [suite.original[s].bytes_per_sec for s in sizes],
        'modified_bps': [suite.modified[s].bytes_per_sec for s in sizes],
        'overhead_pct': [suite.overhead_pct(s) for s in sizes],
    }, 'benchmark_results.json')


def run_collision(repeat: int, max_attempts: int) -> None:
    _section('4 / 4  Partial Collision Search')
    print(f'  Repeat: {repeat} x per config | max_attempts: {max_attempts:,}')

    suite = run_collision_suite(KEY, repeat=repeat, max_attempts=max_attempts)

    configs = suite.configs
    _save_json({
        'configs': [list(c) for c in configs],
        'original_mean_attempts': {
            str(k): suite.original_mean_attempts[k] for k in configs
        },
        'modified_mean_attempts': {
            str(k): suite.modified_mean_attempts[k] for k in configs
        },
        'ratios': {
            str(k): suite.modified_mean_attempts[k] / suite.original_mean_attempts[k]
            for k in configs
        },
    }, 'collision_results.json')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description='Run all SHA-512 experiments.')
    parser.add_argument('--quick', action='store_true',
                        help='Use reduced counts for a fast smoke-test.')
    args = parser.parse_args()

    if args.quick:
        # ── Quick mode: ~1–3 minutes ──────────────────────────────────────
        print('[QUICK MODE] Using reduced sample counts.')
        av_messages, av_len, av_bits = 50, 32, 16
        bic_messages, bic_len, bic_bits = 30, 32, 12
        bench_timing = 50
        coll_repeat, coll_max = 3, 50_000
    else:
        # ── Full mode ─────────────────────────────────────────────────────
        av_messages, av_len, av_bits = 200, 32, 32
        bic_messages, bic_len, bic_bits = 100, 32, 24
        bench_timing = 200
        coll_repeat, coll_max = 5, 200_000

    wall_start = time.perf_counter()

    run_avalanche(av_messages, av_len, av_bits)
    run_bic(bic_messages, bic_len, bic_bits)
    run_bench(bench_timing)
    run_collision(coll_repeat, coll_max)

    _section('Generating Plots')
    os.makedirs(PLOTS_DIR, exist_ok=True)
    plot_avalanche_bic(PLOTS_DIR)
    plot_speed_collision(PLOTS_DIR)

    _section('Summary Report')
    report = generate_summary_report(RESULTS_DIR)

    wall_elapsed = time.perf_counter() - wall_start
    print(f'\n{"=" * 60}')
    print(f'  All experiments complete in {wall_elapsed:.1f}s')
    print(f'  Report : {report.report_path}')
    print(f'  Plots  : {PLOTS_DIR}')
    print(f'{"=" * 60}\n')


if __name__ == '__main__':
    main()
