# Introduction

## 1.1 Background

SHA-512 is a member of the SHA-2 family of cryptographic hash functions, standardised by NIST in FIPS 180-4. It produces a 512-bit (64-byte) digest from an arbitrary-length input and is widely deployed in TLS certificates, digital signatures (ECDSA/RSA), HMAC constructions, and password-based key-derivation functions. Its security rests on three foundational properties: *pre-image resistance*, *second-pre-image resistance*, and *collision resistance*.

## 1.2 The Message Schedule

SHA-512 processes its input in 1024-bit (128-byte) blocks. Each block is expanded from 16 initial 64-bit words into an 80-word *message schedule* W[0..79] using the recursion:

```
W[t] = σ₁(W[t−2]) + W[t−7] + σ₀(W[t−15]) + W[t−16]   (mod 2⁶⁴)
```

where the lower-case sigma functions are defined with **fixed** rotation constants:

```
σ₀(x) = ROTR¹(x) ⊕ ROTR⁸(x) ⊕ SHR⁷(x)
σ₁(x) = ROTR¹⁹(x) ⊕ ROTR⁶¹(x) ⊕ SHR⁶(x)
```

These constants (1, 8, 19, 61) are fixed for all inputs and all keys, making the diffusion trajectory of every hash computation publicly predictable.

## 1.3 Motivation

The determinism of the message schedule, while essential for interoperability, creates a theoretical uniformity in diffusion patterns. An adversary with knowledge of the exact rotation constants can reason about the structure of the expanded schedule, which may slightly ease differential cryptanalysis of reduced-round variants or length-extension attacks in constructions that do not use HMAC.

If the rotation constants in σ₀ and σ₁ were instead *derived from a secret key*, the diffusion pattern would become unpredictable to any party that does not possess the key. This could strengthen the function against differential and related-key attacks without altering the compression function itself.

## 1.4 Project Goals

This project designs, implements, and evaluates a **key-dependent SHA-512 variant** with the following goals:

1. Replace the fixed rotation constants in the message schedule with values derived from a secret key K.
2. Implement both the original and modified variants in pure Python for transparent comparison.
3. Measure the cryptographic impact via four metrics: avalanche effect, bit independence criterion (BIC), partial collision resistance, and computational overhead.
4. Demonstrate that the modification improves or maintains cryptographic strength while keeping overhead below 10%.

## 1.5 Scope and Limitations

This work is a software proof-of-concept aimed at academic evaluation. It does not claim to replace SHA-512 in production systems. The compression round constants K₀–K₇₉ and initial hash values H₀–H₇ are left unchanged. No formal security proof is provided; evaluation is empirical.

All experiments are conducted in Python 3.10+ on a single machine. A minimum of 1,000 test inputs (across all experiments) is used to ensure statistical significance.
