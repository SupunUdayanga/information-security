# Results

> **Note:** This section is populated automatically from the JSON files in `results/`.
> Run all experiments first (`experiments/avalanche_test.py`, `experiments/bic_test.py`,
> `experiments/benchmark.py`, `experiments/partial_collision.py`), then run
> `analysis/results_summary.py` to regenerate the Markdown summary report at
> `results/summary_report.md`.  The tables and figures below describe the expected
> format and interpretation of results.

---

## 3.1 Avalanche Effect

The avalanche effect measures how many output bits change when a single input bit is flipped.
An ideal cryptographic hash function changes exactly 50% (256 / 512) of its output bits on average.

| Variant | Mean Ratio | Std-Dev | ∆ from Ideal |
|---------|-----------|---------|-------------|
| Original SHA-512 | (see summary) | (see summary) | |
| Modified SHA-512 | (see summary) | (see summary) | |

**Figure:** `results/plots/avalanche_comparison.png`

Interpretation:
- A mean ratio closer to 0.5000 is better.
- The modified variant's ratio varies with the key, introducing per-key diffusion diversity.
- The standard deviation reflects the spread of individual trial ratios; a smaller std-dev indicates more consistent avalanche behaviour.

---

## 3.2 Bit Independence Criterion (BIC)

The BIC evaluates whether each of the 512 output bits responds independently to single-bit input changes.
For each output bit position p, we compute the probability that bit p flips when any input bit is flipped.
An ideal hash function produces a flip probability of exactly 0.5 for every output bit.

| Variant | Flip-prob Mean | Flip-prob Std | BIC Score |
|---------|---------------|--------------|-----------|
| Original SHA-512 | (see summary) | (see summary) | (see summary) |
| Modified SHA-512 | (see summary) | (see summary) | (see summary) |

**Figures:**
- `results/plots/bic_score_comparison.png` – BIC score bar chart
- `results/plots/bic_bitprob_heatmap.png` – Per-bit flip probability heatmap

Interpretation:
- A BIC score above 95% means that ≥ 95% of the 512 output bits have flip probabilities in [0.45, 0.55].
- The heatmap visualises whether any output bit regions are systematically biased (red = too low, green = ideal, blue not used here).

---

## 3.3 Hashing Speed

Throughput is measured in KB/s for both variants across five message sizes.
Overhead is the percentage reduction in throughput relative to the original.

| Message Size | Original (KB/s) | Modified (KB/s) | Overhead |
|-------------|----------------|----------------|---------|
| 64 B | (see summary) | (see summary) | |
| 256 B | (see summary) | (see summary) | |
| 1024 B | (see summary) | (see summary) | |
| 4096 B | (see summary) | (see summary) | |
| 16384 B | (see summary) | (see summary) | |

**Figures:**
- `results/plots/speed_throughput.png` – Throughput curves
- `results/plots/speed_overhead.png` – Overhead per message size

Interpretation:
- The key derivation (`SHA-512(K)`) is performed once per `sha512_keydep_hash` call.
- For larger messages (multiple blocks), the per-block overhead of using different rotation constants is minimal (same number of bitwise operations).
- The overhead target is < 10%.

---

## 3.4 Partial Collision Resistance

Reduced-round variants (10, 20, 30 rounds) are used to make birthday-bound collision search tractable.
The ratio `modified_attempts / original_attempts` greater than 1.0 indicates improved resistance.

| Rounds | Bits | Orig Avg Attempts | Mod Avg Attempts | Ratio |
|--------|------|-------------------|-----------------|-------|
| 10 | 16 | (see summary) | (see summary) | |
| 20 | 20 | (see summary) | (see summary) | |
| 30 | 24 | (see summary) | (see summary) | |

**Figures:**
- `results/plots/collision_attempts.png` – Mean attempts (grouped bar chart)
- `results/plots/collision_ratio.png` – Ratio per configuration

Interpretation:
- A ratio > 1 means the key-dependent schedule increases the effort required to find partial collisions.
- Results depend on the key used; the same key is used consistently across all runs for a given experiment.
- The birthday bound predicts 2^(N/2) expected trials; any ratio above 1.0 is statistically significant improvement.
