# sha512-keydep-msgschedule

**EC6204 Information Security — Mini Project**

> Modified SHA-512 with Key-Dependent Message Schedule Rotation Constants

---

## Project Overview

This project implements and evaluates a SHA-512 variant where the rotation constants
in the message schedule σ₀/σ₁ functions are derived from a secret key K:

```
r₀(K) = (K_int mod 19) + 1     # replaces ROTR(1)  in σ₀
r₁(K) = (K_int mod 61) + 1     # replaces ROTR(19) in σ₁
```

All other SHA-512 components remain identical to FIPS 180-4.

---

## Directory Structure

```
sha512-keydep-msgschedule/
├── src/
│   ├── sha512_original.py     # Pure-Python reference SHA-512 implementation
│   ├── sha512_modified.py     # Modified SHA-512 with key-dependent schedule
│   └── key_schedule.py        # Key derivation and schedule word generation
│
├── experiments/
│   ├── avalanche_test.py      # Avalanche effect experiment
│   ├── bic_test.py            # Bit Independence Criterion experiment
│   ├── benchmark.py           # Throughput benchmark
│   └── partial_collision.py   # Partial collision resistance experiment
│
├── analysis/
│   ├── plots_avalanche_bic.py  # Avalanche & BIC plots
│   ├── plots_speed_collision.py # Speed & collision plots
│   └── results_summary.py     # Summary report generator
│
├── report/
│   ├── section_1_intro.md     # Introduction
│   ├── section_2_method.md    # Methodology
│   ├── section_3_results.md   # Results
│   └── section_4_discussion.md # Discussion & Conclusion
│
├── results/                   # Generated JSON results and plots (auto-created)
├── run_all.py                 # Master experiment runner
├── requirements.txt
└── README.md
```

---

## Getting Started like this

### 1. Create a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Quick smoke-test (< 3 minutes)

```powershell
python run_all.py --quick
```

### 4. Full experiment suite (~15–25 minutes in pure Python)

```powershell
python run_all.py
```

Results are saved to `results/`. Plots are saved to `results/plots/`.
The summary report is at `results/summary_report.md`.

---

## Running Individual Experiments

```powershell
# From the project root:
python -m experiments.avalanche_test
python -m experiments.bic_test
python -m experiments.benchmark
python -m experiments.partial_collision
```

### Generate plots only (requires results JSON files)

```powershell
python -m analysis.plots_avalanche_bic
python -m analysis.plots_speed_collision
python -m analysis.results_summary
```

---

## Evaluation Metrics

| Metric | Target | Script |
|--------|--------|--------|
| Avalanche Effect | ≈ 50% (0.500) | `experiments/avalanche_test.py` |
| Bit Independence (BIC) | > 95% | `experiments/bic_test.py` |
| Hashing Speed Overhead | < 10% | `experiments/benchmark.py` |
| Partial Collision Ratio | ≥ 1.0× | `experiments/partial_collision.py` |

---

## Implementation Notes

- Both SHA-512 variants are implemented **from scratch in pure Python** (no `hashlib` is used
  in the core computation) so that algorithmic differences are transparent.
- The key schedule derivation calls `hashlib.sha512(key)` once per hash call to derive
  rotation constants; this is the only use of the standard library hash.
- All random seeds are fixed for reproducibility.
