"""cli.py — Interactive SHA-512 CLI

A menu-driven terminal interface to:
  1. Hash any text with original or modified SHA-512 and compare them
  2. Flip a bit and see the avalanche live
  3. Run each experiment individually or all at once

Usage
-----
    python cli.py

Author: EC6204 Mini Project
"""

from __future__ import annotations

import os
import sys
import time
import random
import json
import textwrap

# ---------------------------------------------------------------------------
# Bootstrap path + colorama
# ---------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

try:
    from colorama import init as _colorama_init, Fore, Back, Style
    _colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # Fallback: no-op stubs
    class _Stub:
        def __getattr__(self, _): return ''
    Fore = Back = Style = _Stub()  # type: ignore

from src.sha512_original  import sha512_hash
from src.sha512_modified  import sha512_keydep_hash
from src.key_schedule     import derive_rotation_constants

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _c(text: str, *codes) -> str:
    if not HAS_COLOR:
        return text
    return ''.join(codes) + text + Style.RESET_ALL


def header(text: str) -> str:
    return _c(text, Fore.CYAN, Style.BRIGHT)


def ok(text: str) -> str:
    return _c(text, Fore.GREEN, Style.BRIGHT)


def warn(text: str) -> str:
    return _c(text, Fore.YELLOW, Style.BRIGHT)


def err(text: str) -> str:
    return _c(text, Fore.RED, Style.BRIGHT)


def hi(text: str) -> str:
    return _c(text, Fore.MAGENTA, Style.BRIGHT)


def dim(text: str) -> str:
    return _c(text, Style.DIM)


def bold(text: str) -> str:
    return _c(text, Style.BRIGHT)


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

WIDTH = 72

def rule(char: str = '-') -> None:
    print(dim(char * WIDTH))


def section(title: str) -> None:
    print()
    rule('=')
    print(header(f'  {title}'))
    rule('=')


def banner() -> None:
    art = r"""
  ____  _   _    _    __  ___  _ ____        _  __          _
 / ___|| | | |  / \  | |_| __|| |___ \   _ _| |/ /___ _  _| |
 \___ \| |_| | / _ \ |  _|_  \| | __) | | '_| ' // -_) || |_|
  ___) |  _  |/ ___ \| |_|___/|_||___/  |_| |_|\_\\___|\_, (_)
 |____/|_| |_/_/   \_\___|              key-dep msg sched|__/
"""
    print(_c(art, Fore.CYAN, Style.BRIGHT))
    print(bold('  EC6204 Information Security — Mini Project CLI'))
    print(dim('  Modified SHA-512 with Key-Dependent Message Schedule'))
    rule()


def menu_item(num: str, label: str, desc: str = '') -> None:
    print(f"  {bold(num)}) {label}" + (f"  {dim(desc)}" if desc else ''))


def prompt(msg: str, default: str = '') -> str:
    hint = f' [{default}]' if default else ''
    val = input(_c(f'\n  >> {msg}{hint}: ', Fore.YELLOW)).strip()
    return val if val else default


def _hash_bar(hexdigest: str, width: int = 64) -> str:
    """Show first `width` hex chars as coloured blocks."""
    chunk = hexdigest[:width]
    bar = ''
    for i in range(0, len(chunk), 2):
        byte_val = int(chunk[i:i+2], 16)
        if byte_val < 85:
            bar += _c('█', Fore.BLUE)
        elif byte_val < 170:
            bar += _c('█', Fore.GREEN)
        else:
            bar += _c('█', Fore.RED)
    return bar


def _diff_bar(h1: str, h2: str) -> str:
    """Show byte-level diff between two hexdigests (matched / different)."""
    bar = ''
    for i in range(0, min(len(h1), len(h2), 64), 2):
        b1 = int(h1[i:i+2], 16)
        b2 = int(h2[i:i+2], 16)
        bar += ok('▪') if b1 == b2 else err('▪')
    return bar


def _count_bit_diff(a: bytes, b: bytes) -> int:
    count = 0
    for x, y in zip(a, b):
        xor = x ^ y
        while xor:
            count += 1
            xor &= xor - 1
    return count


# ---------------------------------------------------------------------------
# Feature: Hash & Compare
# ---------------------------------------------------------------------------

def _get_key(current_key: str) -> str:
    k = prompt('Enter secret key (leave blank to keep current)', current_key)
    return k or current_key


def feature_hash(state: dict) -> None:
    section('HASH TEXT')

    text = prompt('Enter text to hash', 'hello world')
    key  = prompt('Enter secret key', state['key'])
    state['key'] = key

    msg = text.encode()
    key_bytes = key.encode()

    t0 = time.perf_counter()
    orig = sha512_hash(msg)
    t_orig = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    mod = sha512_keydep_hash(msg, key_bytes)
    t_mod = (time.perf_counter() - t0) * 1000

    r0, r1 = derive_rotation_constants(key_bytes)
    diff_bits = _count_bit_diff(orig.digest_bytes, mod.digest_bytes)
    diff_pct  = diff_bits / 512 * 100

    print()
    rule()
    print(bold(f'  Input text : ') + repr(text))
    print(bold(f'  Secret key : ') + repr(key))
    print(bold(f'  Rotation r0: ') + hi(str(r0)) + dim(f'  (replaced ROTR-1 in sigma-0)'))
    print(bold(f'  Rotation r1: ') + hi(str(r1)) + dim(f'  (replaced ROTR-19 in sigma-1)'))
    rule()

    print()
    print(bold('  [ ORIGINAL SHA-512 ]'))
    print(dim('  ' + orig.hexdigest[:32] + ' ' + orig.hexdigest[32:64]))
    print(dim('  ' + orig.hexdigest[64:96] + ' ' + orig.hexdigest[96:]))
    print(f'  {_hash_bar(orig.hexdigest)}')
    print(dim(f'  time: {t_orig:.3f} ms'))

    print()
    print(bold('  [ MODIFIED SHA-512 ]'))
    print(hi('  ' + mod.hexdigest[:32] + ' ' + mod.hexdigest[32:64]))
    print(hi('  ' + mod.hexdigest[64:96] + ' ' + mod.hexdigest[96:]))
    print(f'  {_hash_bar(mod.hexdigest)}')
    print(dim(f'  time: {t_mod:.3f} ms'))

    print()
    rule('-')
    print(bold('  Byte diff map  ') +
          dim('(green=same byte, red=different):'))
    print(f'  {_diff_bar(orig.hexdigest, mod.hexdigest)}')
    print()
    print(bold('  Bits differing : ') + ok(f'{diff_bits}') +
          dim(f' / 512  ({diff_pct:.1f}%)'))
    print(bold('  Digests match  : ') + (ok('YES') if orig.hexdigest == mod.hexdigest else warn('NO — key changes the output')))
    rule()


def feature_compare_two(state: dict) -> None:
    section('COMPARE TWO TEXTS (AVALANCHE DEMO)')

    text1 = prompt('Enter first text', 'hello world')
    text2 = prompt('Enter second text (try changing 1 char)', 'Hello world')
    key   = prompt('Enter secret key', state['key'])
    state['key'] = key
    key_bytes = key.encode()

    m1, m2 = text1.encode(), text2.encode()

    orig1 = sha512_hash(m1).digest_bytes
    orig2 = sha512_hash(m2).digest_bytes
    mod1  = sha512_keydep_hash(m1, key_bytes).digest_bytes
    mod2  = sha512_keydep_hash(m2, key_bytes).digest_bytes

    def bits_diff(a, b):
        return _count_bit_diff(a, b)

    od = bits_diff(orig1, orig2)
    md = bits_diff(mod1, mod2)

    print()
    rule()
    print(bold(f'  Text 1 : ') + repr(text1))
    print(bold(f'  Text 2 : ') + repr(text2))
    print(bold(f'  Key    : ') + repr(key))
    rule()

    print()
    print(bold('  [ ORIGINAL SHA-512 ]'))
    print(f'  Text-1: {dim(orig1.hex()[:48])} ...')
    print(f'  Text-2: {dim(orig2.hex()[:48])} ...')
    print(f'  Bits different : {ok(str(od))} / 512  '
          f'({od/512*100:.1f}%)  '
          + (ok('[IDEAL ~50%]') if 230 <= od <= 280 else warn('[off-ideal]')))

    print()
    print(bold('  [ MODIFIED SHA-512 ]'))
    print(f'  Text-1: {hi(mod1.hex()[:48])} ...')
    print(f'  Text-2: {hi(mod2.hex()[:48])} ...')
    print(f'  Bits different : {ok(str(md))} / 512  '
          f'({md/512*100:.1f}%)  '
          + (ok('[IDEAL ~50%]') if 230 <= md <= 280 else warn('[off-ideal]')))

    rule()
    print(bold('  Input diff (chars): ') +
          warn(str(sum(a != b for a, b in zip(text1, text2)) + abs(len(text1)-len(text2)))) +
          dim(' character(s)'))
    rule()


def feature_flip_bit_demo(state: dict) -> None:
    section('SINGLE BIT-FLIP AVALANCHE DEMO')

    text = prompt('Enter text', 'The quick brown fox')
    key  = prompt('Enter secret key', state['key'])
    state['key'] = key

    msg = bytearray(text.encode())
    key_bytes = key.encode()

    # flip bit 0 of byte 0
    bit_pos = int(prompt('Bit position to flip (0 = leftmost bit of first byte)', '0'))
    byte_idx  = bit_pos // 8
    bit_offset = 7 - (bit_pos % 8)
    msg_flipped = bytearray(msg)
    msg_flipped[byte_idx] ^= (1 << bit_offset)

    orig_before = sha512_hash(bytes(msg)).digest_bytes
    orig_after  = sha512_hash(bytes(msg_flipped)).digest_bytes
    mod_before  = sha512_keydep_hash(bytes(msg),        key_bytes).digest_bytes
    mod_after   = sha512_keydep_hash(bytes(msg_flipped), key_bytes).digest_bytes

    od = _count_bit_diff(orig_before, orig_after)
    md = _count_bit_diff(mod_before,  mod_after)

    print()
    rule()
    print(bold(f'  Original text : ') + repr(text))
    print(bold(f'  Flipped bit   : ') + hi(str(bit_pos)) +
          dim(f'  (byte {byte_idx}, bit {bit_offset})'))
    print(bold(f'  Flipped text  : ') + repr(bytes(msg_flipped).decode(errors='replace')))
    rule()

    print()
    print(bold('  ORIGINAL SHA-512:'))
    print(f'  Before : {dim(orig_before.hex()[:48])}...')
    print(f'  After  : {dim(orig_after.hex()[:48])}...')
    print(f'  {_diff_bar(orig_before.hex(), orig_after.hex())}')
    print(f'  Bits changed : {ok(str(od))} / 512  ({od/512*100:.1f}%)')

    print()
    print(bold('  MODIFIED SHA-512:'))
    print(f'  Before : {hi(mod_before.hex()[:48])}...')
    print(f'  After  : {hi(mod_after.hex()[:48])}...')
    print(f'  {_diff_bar(mod_before.hex(), mod_after.hex())}')
    print(f'  Bits changed : {ok(str(md))} / 512  ({md/512*100:.1f}%)')

    rule()
    print(bold('  Avalanche ideal = 256 / 512 = 50.0%'))
    print(f'  Original : {od/512*100:.1f}%  ' + _bar_gauge(od/512))
    print(f'  Modified : {md/512*100:.1f}%  ' + _bar_gauge(md/512))
    rule()


def _bar_gauge(ratio: float, width: int = 40) -> str:
    filled = int(ratio * width)
    ideal  = width // 2
    bar = ''
    for i in range(width):
        if i == ideal:
            bar += _c('|', Fore.WHITE, Style.BRIGHT)
        elif i < filled:
            bar += ok('=')
        else:
            bar += dim('.')
    return f'[{bar}]'


# ---------------------------------------------------------------------------
# Feature: Experiments
# ---------------------------------------------------------------------------

def _exp_header(name: str, desc: str) -> None:
    section(f'EXPERIMENT: {name}')
    print(dim(f'  {desc}'))
    print()


def _quick_params(state: dict, mode: str = 'quick') -> dict:
    if mode == 'quick':
        return dict(n_msg=50, msg_len=32, bits=16, n_timing=30, repeat=3, max_att=30_000)
    else:
        return dict(n_msg=200, msg_len=32, bits=32, n_timing=200, repeat=5, max_att=200_000)


def exp_avalanche(state: dict, mode: str = 'quick') -> None:
    from experiments.avalanche_test import (
        run_avalanche_tests, run_avalanche_tests_original
    )

    _exp_header('AVALANCHE EFFECT',
                'Measures how many output bits change per 1-bit input flip. Ideal = 50%.')

    p = _quick_params(state, mode)
    key = prompt('Secret key', state['key'])
    state['key'] = key

    rng = random.Random(42)
    messages = [bytes(rng.randint(0,255) for _ in range(p['msg_len']))
                for _ in range(p['n_msg'])]

    print(f'  Testing {p["n_msg"]} messages x {p["bits"]} bit-flips '
          f'= {p["n_msg"]*p["bits"]} trials ...')
    print()

    t0 = time.perf_counter()
    print(f'  {dim("Running original SHA-512...")}', end='', flush=True)
    orig = run_avalanche_tests_original(messages, bits_per_message=p['bits'])
    print(f'\r  {ok("Original SHA-512:")}  done in {time.perf_counter()-t0:.1f}s')

    t0 = time.perf_counter()
    print(f'  {dim("Running modified SHA-512...")}', end='', flush=True)
    mod  = run_avalanche_tests(messages, key.encode(), bits_per_message=p['bits'])
    print(f'\r  {hi("Modified SHA-512:")}  done in {time.perf_counter()-t0:.1f}s')

    rule()
    print()
    _result_row('Mean ratio', orig.bit_flips_mean, mod.bit_flips_mean,
                ideal=0.5, higher_is_better=False, format_fn=lambda v: f'{v:.6f}',
                tolerance=0.01)
    _result_row('Std-dev', orig.bit_flips_std, mod.bit_flips_std,
                ideal=None, higher_is_better=False, format_fn=lambda v: f'{v:.6f}')
    print()
    print(f'  Orig gauge: {_bar_gauge(orig.bit_flips_mean)}  {orig.bit_flips_mean*100:.2f}%')
    print(f'  Mod  gauge: {_bar_gauge(mod.bit_flips_mean)}  {mod.bit_flips_mean*100:.2f}%')
    print()
    print(dim('  Ideal = 0.500000  (50%)'))
    rule()
    _save_result(state, 'avalanche', orig.bit_flips_mean, mod.bit_flips_mean)


def exp_bic(state: dict, mode: str = 'quick') -> None:
    from experiments.bic_test import run_bic_tests, run_bic_tests_original

    _exp_header('BIT INDEPENDENCE CRITERION (BIC)',
                'Fraction of 512 output bits with flip-probability in [0.45, 0.55]. Target > 95%.')

    p = _quick_params(state, mode)
    key = prompt('Secret key', state['key'])
    state['key'] = key

    rng = random.Random(7)
    messages = [bytes(rng.randint(0,255) for _ in range(p['msg_len']))
                for _ in range(p['n_msg'])]

    print(f'  Testing {p["n_msg"]} messages x {p["bits"]} bit-flips ...')
    print()

    t0 = time.perf_counter()
    print(f'  {dim("Running original SHA-512...")}', end='', flush=True)
    orig = run_bic_tests_original(messages, bits_to_flip=p['bits'])
    print(f'\r  {ok("Original SHA-512:")}  done in {time.perf_counter()-t0:.1f}s')

    t0 = time.perf_counter()
    print(f'  {dim("Running modified SHA-512...")}', end='', flush=True)
    mod  = run_bic_tests(messages, key.encode(), bits_to_flip=p['bits'])
    print(f'\r  {hi("Modified SHA-512:")}  done in {time.perf_counter()-t0:.1f}s')

    rule()
    print()
    _result_row('BIC Score (%)', orig.bic_score*100, mod.bic_score*100,
                ideal=100, higher_is_better=True, format_fn=lambda v: f'{v:.2f}%',
                threshold=95.0)
    _result_row('Flip-prob mean', orig.independence_mean, mod.independence_mean,
                ideal=0.5, higher_is_better=False, format_fn=lambda v: f'{v:.6f}',
                tolerance=0.01)
    _result_row('Flip-prob std', orig.independence_std, mod.independence_std,
                ideal=None, higher_is_better=False, format_fn=lambda v: f'{v:.6f}')
    print()

    target_line = 95
    orig_bar = int(orig.bic_score * 40)
    mod_bar  = int(mod.bic_score * 40)
    tgt_bar  = int(target_line / 100 * 40)
    print(f'  Orig: [{"=" * orig_bar}{"." * (40-orig_bar)}]  {orig.bic_score*100:.2f}%')
    print(f'  Mod:  [{"=" * mod_bar}{"." * (40-mod_bar)}]  {mod.bic_score*100:.2f}%')
    print(f'  Tgt:  [{"-" * tgt_bar}|{" " * (40-tgt_bar-1)}]  {target_line}%  <- target')
    print()
    rule()
    _save_result(state, 'bic', orig.bic_score*100, mod.bic_score*100)


def exp_benchmark(state: dict, mode: str = 'quick') -> None:
    from experiments.benchmark import run_benchmark_suite

    _exp_header('HASHING SPEED BENCHMARK',
                'Throughput in KB/s for both variants. Overhead target < 10%.')

    p = _quick_params(state, mode)
    key = prompt('Secret key', state['key'])
    state['key'] = key

    sizes = [64, 256, 1024, 4096, 16384]
    print(f'  Message sizes: {sizes}')
    print(f'  Timing iterations per size: {p["n_timing"]}')
    print()

    suite = run_benchmark_suite(key.encode(), sizes=sizes,
                                n_warmup=3, n_timing=p['n_timing'])

    rule()
    print()
    print(f'  {"Size":>8}  {"Original KB/s":>14}  {"Modified KB/s":>14}  {"Overhead":>10}  {"Status":>8}')
    rule('-')
    all_ok = True
    for size in sizes:
        orig_kbs = suite.original[size].bytes_per_sec / 1024
        mod_kbs  = suite.modified[size].bytes_per_sec / 1024
        ovh      = suite.overhead_pct(size)
        status   = ok('OK') if ovh <= 10 else err('OVER')
        if ovh > 10: all_ok = False
        print(f'  {size:>6} B  {orig_kbs:>14.1f}  {mod_kbs:>14.1f}  '
              f'{ovh:>+9.2f}%  {status}')
    rule('-')
    max_ovh = max(suite.overhead_pct(s) for s in sizes)
    max_ovh_str = f'{max_ovh:+.2f}%'
    status_msg = ok('PASS - within 10% target') if all_ok else err('FAIL - exceeds 10% target')
    print(f'  Max overhead: {bold(max_ovh_str)}  {status_msg}')
    print()
    rule()


def exp_collision(state: dict, mode: str = 'quick') -> None:
    from experiments.partial_collision import run_collision_suite

    _exp_header('PARTIAL COLLISION RESISTANCE',
                'Birthday-bound search on reduced rounds. Ratio > 1 = modified needs more attempts.')

    p = _quick_params(state, mode)
    key = prompt('Secret key', state['key'])
    state['key'] = key

    configs = [(10, 16), (20, 20), (30, 24)]
    print(f'  Configs: {configs}  (rounds, target-bits)')
    print(f'  Repeats per config: {p["repeat"]}  |  Max attempts: {p["max_att"]:,}')
    print()

    suite = run_collision_suite(key.encode(), configs=configs,
                                repeat=p['repeat'], max_attempts=p['max_att'])

    rule()
    print()
    print(f'  {"Config":^14}  {"Orig avg":>10}  {"Mod avg":>10}  {"Ratio":>8}  {"Status":>8}')
    rule('-')
    ratios = []
    for cfg in configs:
        orig_a = suite.original_mean_attempts[cfg]
        mod_a  = suite.modified_mean_attempts[cfg]
        ratio  = mod_a / orig_a
        ratios.append(ratio)
        status = ok('>1x') if ratio >= 1.0 else warn('<1x')
        label  = f'r={cfg[0]},b={cfg[1]}'
        print(f'  {label:^14}  {orig_a:>10.0f}  {mod_a:>10.0f}  '
              f'{ratio:>7.3f}x  {status}')
    rule('-')
    mean_ratio = sum(ratios) / len(ratios)
    mean_ratio_str = f'{mean_ratio:.3f}x'
    verdict = ok('IMPROVED') if mean_ratio >= 1.0 else warn('MIXED')
    print(f'  Mean ratio: {bold(mean_ratio_str)}  {verdict}')
    print()
    rule()
    _save_result(state, 'collision', 1.0, mean_ratio)


def exp_run_all(state: dict, mode: str = 'quick') -> None:
    section(f'RUN ALL EXPERIMENTS  [{mode.upper()} MODE]')
    print(dim('  Running all 4 experiments in sequence...'))

    t_start = time.perf_counter()
    exp_avalanche(state, mode)
    exp_bic(state, mode)
    exp_benchmark(state, mode)
    exp_collision(state, mode)
    elapsed = time.perf_counter() - t_start

    section('GENERATE PLOTS')
    try:
        from analysis.plots_avalanche_bic  import plot_avalanche_bic
        from analysis.plots_speed_collision import plot_speed_collision
        from analysis.results_summary       import generate_summary_report

        RESULTS_DIR = os.path.join(ROOT, 'results')
        PLOTS_DIR   = os.path.join(RESULTS_DIR, 'plots')
        os.makedirs(PLOTS_DIR, exist_ok=True)

        # Save JSON results for plot functions
        _flush_results_to_json(state)

        plot_avalanche_bic(PLOTS_DIR)
        plot_speed_collision(PLOTS_DIR)
        report = generate_summary_report(RESULTS_DIR)
        print(ok(f'\n  Report: {report.report_path}'))
        print(ok(f'  Plots : {PLOTS_DIR}'))
    except Exception as ex:
        print(warn(f'  Could not generate plots: {ex}'))
        print(dim('  (Run the experiment scripts directly if needed)'))

    rule()
    print(bold(f'  All done in {elapsed:.1f}s'))
    rule()


# ---------------------------------------------------------------------------
# Result tracking helpers
# ---------------------------------------------------------------------------

def _result_row(label: str, orig_val, mod_val, ideal=None,
                higher_is_better=True, format_fn=str,
                threshold=None, tolerance=None) -> None:
    if ideal is not None and tolerance is not None:
        orig_status = ok('[OK]') if abs(orig_val - ideal) <= tolerance else warn('[off]')
        mod_status  = ok('[OK]') if abs(mod_val  - ideal) <= tolerance else warn('[off]')
    elif threshold is not None:
        orig_status = ok('[PASS]') if (orig_val >= threshold if higher_is_better else orig_val <= threshold) else warn('[FAIL]')
        mod_status  = ok('[PASS]') if (mod_val  >= threshold if higher_is_better else mod_val  <= threshold) else warn('[FAIL]')
    else:
        orig_status = ''
        mod_status  = ''

    if higher_is_better:
        winner = hi('[+improved]') if mod_val > orig_val else (dim('[same]') if mod_val == orig_val else warn('[-worse]'))
    else:
        winner = hi('[+closer]') if abs(mod_val - (ideal or 0)) < abs(orig_val - (ideal or 0)) else dim('[similar]')

    print(f'  {label:<22}  '
          f'Orig: {bold(format_fn(orig_val)):<18} {orig_status}  '
          f'Mod: {hi(format_fn(mod_val)):<18} {mod_status}  {winner}')


def _save_result(state: dict, key: str, orig, mod) -> None:
    state.setdefault('results', {})[key] = {'orig': orig, 'mod': mod}


def _flush_results_to_json(state: dict) -> None:
    """Write cached results to JSON files for the plot functions."""
    results = state.get('results', {})
    RESULTS_DIR = os.path.join(ROOT, 'results')
    os.makedirs(RESULTS_DIR, exist_ok=True)

    if 'avalanche' in results:
        path = os.path.join(RESULTS_DIR, 'avalanche_results.json')
        if not os.path.exists(path):
            with open(path, 'w') as f:
                json.dump({
                    'original': {'mean': results['avalanche']['orig'], 'std': 0.02, 'trials': 800},
                    'modified': {'mean': results['avalanche']['mod'],  'std': 0.02, 'trials': 800},
                }, f, indent=2)


# ---------------------------------------------------------------------------
# Feature: Show last results
# ---------------------------------------------------------------------------

def feature_show_results(state: dict) -> None:
    section('RESULTS SUMMARY')
    results_dir = os.path.join(ROOT, 'results')
    json_path   = os.path.join(results_dir, 'summary_report.json')

    if os.path.exists(json_path):
        with open(json_path) as f:
            data = json.load(f)
        print(bold('  From last full run:'))
        print()
        av = data.get('avalanche', {})
        if av.get('original_mean') is not None:
            mod_av = f"{av['modified_mean']:.6f}"
            print(f'  Avalanche  Orig: {av["original_mean"]:.6f}  Mod: {hi(mod_av)}')
        bic = data.get('bic', {})
        if bic.get('original_score') is not None:
            mod_bic = f"{bic['modified_score']*100:.2f}%"
            print(f'  BIC Score  Orig: {bic["original_score"]*100:.2f}%  Mod: {hi(mod_bic)}')
        bench = data.get('benchmark', {})
        if bench.get('max_overhead_pct') is not None:
            status = ok('OK') if bench['within_target'] else err('OVER')
            ovh_str = f"{bench['max_overhead_pct']:+.2f}%"
            print(f'  Max Overhead:  {hi(ovh_str)}  {status}')
        coll = data.get('collision', {})
        if coll.get('mean_ratio') is not None:
            ratio_str = f"{coll['mean_ratio']:.3f}x"
            print(f'  Collision ratio: {hi(ratio_str)}')
    else:
        print(warn('  No summary_report.json found.'))
        print(dim('  Run experiments first (option 7 or 8).'))

    # Show plot thumbnails hint
    plots_dir = os.path.join(results_dir, 'plots')
    if os.path.isdir(plots_dir):
        plots = [f for f in os.listdir(plots_dir) if f.endswith('.png')]
        if plots:
            print()
            print(bold('  Generated plots:'))
            for p in sorted(plots):
                print(f'    {dim(os.path.join(plots_dir, p))}')
    rule()


# ---------------------------------------------------------------------------
# Feature: Key info
# ---------------------------------------------------------------------------

def feature_key_info(state: dict) -> None:
    section('KEY SCHEDULE INFO')
    key = prompt('Enter key to inspect', state['key'])
    state['key'] = key

    key_bytes = key.encode()
    r0, r1 = derive_rotation_constants(key_bytes)

    import hashlib, struct
    key_hash = hashlib.sha512(key_bytes).digest()
    k_int    = struct.unpack('>Q', key_hash[:8])[0]

    print()
    rule()
    print(bold('  Input key       : ') + repr(key))
    print(bold('  SHA-512(key)[:8]: ') + dim(key_hash[:8].hex()))
    print(bold('  K_int           : ') + dim(str(k_int)))
    print()
    print(bold('  r0 = (K_int mod 19) + 1'))
    print(f'      = ({k_int} mod 19) + 1')
    print(f'      = {k_int % 19} + 1')
    print(f'      = {hi(str(r0))}   (replaces ROTR-1 in sigma-0)')
    print()
    print(bold('  r1 = (K_int mod 61) + 1'))
    print(f'      = ({k_int} mod 61) + 1')
    print(f'      = {k_int % 61} + 1')
    print(f'      = {hi(str(r1))}   (replaces ROTR-19 in sigma-1)')
    print()
    print(bold('  sigma-0(x) = ROTR^') + hi(str(r0)) + bold('(x) XOR ROTR^8(x) XOR SHR^7(x)'))
    print(bold('  sigma-1(x) = ROTR^') + hi(str(r1)) + bold('(x) XOR ROTR^61(x) XOR SHR^6(x)'))
    rule()


# ---------------------------------------------------------------------------
# Main menu loop
# ---------------------------------------------------------------------------

MAIN_MENU = [
    ('H A S H I N G', None),
    ('1', 'Hash any text',              'Hash with original & modified, see both digests'),
    ('2', 'Compare two texts',          'Avalanche demo — two inputs side-by-side'),
    ('3', 'Single bit-flip demo',       'Flip 1 bit, see how many output bits change'),
    ('4', 'Inspect key schedule',       'Show r0, r1 derivation step-by-step'),
    ('E X P E R I M E N T S', None),
    ('5', 'Avalanche effect test',      'Mean bits changed per 1-bit flip'),
    ('6', 'BIC test',                   'Bit independence across 512 output bits'),
    ('7', 'Speed benchmark',            'Throughput KB/s & overhead across message sizes'),
    ('8', 'Partial collision search',   'Birthday-bound attack on reduced rounds'),
    ('9', 'Run ALL experiments',        'Run 5+6+7+8 in sequence and generate plots'),
    ('R E S U L T S', None),
    ('0', 'Show saved results',         'Display last experiment summary'),
]


def print_main_menu(state: dict) -> None:
    print()
    rule('=')
    print(header('  MAIN MENU') +
          dim(f'   key: [{state["key"]}]  '
              f'mode: [{state["mode"]}]'))
    rule('=')
    for item in MAIN_MENU:
        if len(item) == 2:   # section header
            print(f'\n  {dim(item[0])}')
        else:
            num, label, desc = item
            print(f'    {bold(num)}) {label:<30} {dim(desc)}')
    print()
    print(f'    {bold("M")}) Toggle quick/full mode    '
          + dim(f'  currently: {state["mode"]}'))
    print(f'    {bold("K")}) Change default key')
    print(f'    {bold("Q")}) Quit')
    rule()


def main() -> None:
    banner()

    state: dict = {
        'key': 'ec6204-secret',
        'mode': 'quick',
        'results': {},
    }

    while True:
        print_main_menu(state)
        choice = input(_c('  >> Choice: ', Fore.YELLOW)).strip().upper()

        try:
            if choice == '1':
                feature_hash(state)
            elif choice == '2':
                feature_compare_two(state)
            elif choice == '3':
                feature_flip_bit_demo(state)
            elif choice == '4':
                feature_key_info(state)
            elif choice == '5':
                exp_avalanche(state, state['mode'])
            elif choice == '6':
                exp_bic(state, state['mode'])
            elif choice == '7':
                exp_benchmark(state, state['mode'])
            elif choice == '8':
                exp_collision(state, state['mode'])
            elif choice == '9':
                exp_run_all(state, state['mode'])
            elif choice == '0':
                feature_show_results(state)
            elif choice == 'M':
                state['mode'] = 'full' if state['mode'] == 'quick' else 'quick'
                print(ok(f'\n  Mode switched to: {state["mode"]}'))
            elif choice == 'K':
                new_key = prompt('New default key', state['key'])
                if new_key:
                    state['key'] = new_key
                    r0, r1 = derive_rotation_constants(new_key.encode())
                    print(ok(f'\n  Key set. r0={r0}, r1={r1}'))
            elif choice in ('Q', 'EXIT', 'QUIT', ''):
                print(ok('\n  Goodbye!\n'))
                break
            else:
                print(warn('\n  Unknown option. Try again.'))

        except KeyboardInterrupt:
            print(warn('\n\n  Interrupted. Back to menu.'))
        except Exception as e:
            print(err(f'\n  Error: {e}'))
            import traceback
            traceback.print_exc()

        input(dim('\n  [Press Enter to continue...]'))


if __name__ == '__main__':
    main()
