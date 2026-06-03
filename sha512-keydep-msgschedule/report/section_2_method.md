# Methodology

## 2.1 Modification Design

### 2.1.1 Key Schedule

Given a secret key K (arbitrary byte string), the rotation constants are derived as follows:

1. Compute `K_hash = SHA-512(K)` (standard SHA-512 of the raw key bytes).
2. Interpret the first 8 bytes of `K_hash` as a big-endian 64-bit unsigned integer `K_int`.
3. Derive:

```
r₀ = (K_int mod 19) + 1       ∈ {1, …, 19}
r₁ = (K_int mod 61) + 1       ∈ {1, …, 61}
```

Using `SHA-512(K)` as the source of `K_int` ensures that even low-entropy keys (e.g., short passwords) produce well-distributed rotation values. The modulo bounds are chosen to stay within the valid range for 64-bit rotations while matching the original constants' orders of magnitude.

### 2.1.2 Modified σ Functions

The message schedule expansion is changed to:

```
σ₀(x, K) = ROTR^r₀(x) ⊕ ROTR⁸(x) ⊕ SHR⁷(x)
σ₁(x, K) = ROTR^r₁(x) ⊕ ROTR⁶¹(x) ⊕ SHR⁶(x)
```

Only the *first* rotation in each σ function is replaced. The secondary rotations (8, 61) and shifts (7, 6) are kept fixed because the proposal targets r₀ and r₁ specifically, and varying all constants independently would move outside the stated scope.

### 2.1.3 Modified Message Schedule

```
W[t] = σ₁(W[t−2], K) + W[t−7] + σ₀(W[t−15], K) + W[t−16]   (mod 2⁶⁴)
```

All other SHA-512 components (padding, compression rounds, round constants K₀–K₇₉, initial hash values H₀–H₇) remain unchanged.

## 2.2 Implementation

### 2.2.1 File Structure

| File | Description |
|------|-------------|
| `src/sha512_original.py` | Pure-Python RFC-6234-compliant SHA-512 |
| `src/key_schedule.py` | Key derivation and modified message schedule |
| `src/sha512_modified.py` | Modified SHA-512 using key-dependent σ₀/σ₁ |

Both implementations are written from scratch (no `hashlib` used in the core computation) so that the algorithm-level differences are transparent and verifiable.

### 2.2.2 Correctness Verification

The original implementation is verified against the standard FIPS 180-4 test vectors before any experiments are run. The modified implementation is verified to produce a different, but deterministic, digest for the same message with the same key.

## 2.3 Experiments

### 2.3.1 Avalanche Effect

- **Tool:** `experiments/avalanche_test.py`
- **Method:** For each of N=200 random 32-byte messages and B=32 bit-flip positions, the original and modified hashes are computed before and after the flip. The Hamming distance (number of output bits that differ) is divided by 512 to give the *avalanche ratio*.
- **Metric:** Mean and standard deviation of avalanche ratios over all trials (N × B = 6,400 trials per variant).
- **Target:** Mean ratio ≈ 0.5 (50%).

### 2.3.2 Bit Independence Criterion (BIC)

- **Tool:** `experiments/bic_test.py`
- **Method:** For each of the 512 output bit positions p, compute the fraction of (message, bit-flip) trials in which bit p changes. The resulting distribution across p should be tightly concentrated around 0.5. The *BIC score* is the percentage of output bits whose flip probability falls in the interval [0.45, 0.55].
- **Metric:** Mean flip probability, std-dev, and BIC score.
- **Target:** BIC score > 95%.

### 2.3.3 Hashing Speed

- **Tool:** `experiments/benchmark.py`
- **Method:** For each message size S ∈ {64, 256, 1024, 4096, 16384} bytes, 200 timed hash operations are performed after 5 warm-up calls. Throughput is measured in KB/s. Overhead is calculated as `(orig_speed − mod_speed) / orig_speed × 100`.
- **Target:** Maximum overhead < 10%.

### 2.3.4 Partial Collision Resistance

- **Tool:** `experiments/partial_collision.py`
- **Method:** Using reduced-round variants (10, 20, 30 rounds out of 80), a birthday-paradox search is run to find two distinct messages whose hash digests agree on the first N bits (N ∈ {16, 20, 24}). The mean number of attempts over 5 independent runs is recorded. The ratio `mod_attempts / orig_attempts` measures resistance improvement.
- **Target:** Ratio ≥ 1.0 (modified variant requires at least as many attempts as original).

## 2.4 Statistical Validity

All experiment results are based on ≥ 1,000 independently sampled inputs in aggregate. Random seeds are fixed for reproducibility but differ per experiment. Results are stored as JSON in `results/` and visualised by `analysis/plots_*.py`.
