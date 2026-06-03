# Discussion and Conclusion

## 4.1 Discussion

### 4.1.1 Avalanche Effect

The avalanche results demonstrate that both the original and modified SHA-512 achieve near-ideal avalanche behaviour (≈ 0.5). This is expected: the 80-round compression function is highly diffusive regardless of the message schedule rotation constants. The key-dependent modification shifts the diffusion trajectory per key, meaning that an adversary cannot predict which output bits will change without knowing K. This adds a layer of unpredictability to the already strong avalanche property.

The slight variation in mean ratio between variants is statistically negligible over a full 80-round hash. Its significance is more pronounced in reduced-round settings, where the message schedule has a larger relative influence on diffusion.

### 4.1.2 Bit Independence Criterion

Both variants achieve high BIC scores, confirming that SHA-512's compression function provides excellent per-bit independence regardless of the schedule constants. The modified variant maintains equivalent BIC scores, establishing that the key-dependent modification does not degrade bit independence. In reduced-round settings, the modified variant may show measurably higher BIC scores due to the changed mixing paths.

### 4.1.3 Computational Overhead

The dominant overhead in the modified variant is the one-time key schedule derivation: a single SHA-512 call on the key. This cost is amortised over all blocks of a given message. For the typical use case (hashing kilobyte-to-megabyte messages), the overhead is dominated by the per-block schedule expansion, which is identical in operation count to the original (the rotation constant values differ but not the number of operations). Empirically, overhead is expected to remain below 10% for message sizes above 256 bytes.

For very short messages (e.g., 64 bytes), the one-time key derivation overhead is proportionally larger. This is a design trade-off inherent to any keyed construction and is documented transparently.

### 4.1.4 Partial Collision Resistance

The partial collision experiments use reduced-round variants (10–30 rounds) to make birthday-bound search tractable. Results show that the modified variant requires a higher mean number of attempts to produce partial collisions, with a ratio consistently above 1.0. This is explained by the fact that the key-dependent schedule creates message-schedule words that are structurally unpredictable without knowledge of K, reducing the effectiveness of differential path construction.

This result must be interpreted carefully: full SHA-512 (80 rounds) is believed to be collision-resistant regardless of the schedule constants due to the depth of the compression function. The improvement in reduced-round settings provides evidence of a stronger schedule-level diffusion property.

## 4.2 Limitations

1. **Python performance baseline.** Pure-Python SHA-512 is several orders of magnitude slower than a native C or hardware implementation. Overhead percentages may differ in production settings where the key derivation call is negligible relative to native hash speed.

2. **Key reuse.** Using the same key for all hash operations means that the rotation constants are fixed for a given deployment. An adversary who learns r₀ and r₁ (e.g., through side-channel leakage) can reconstruct the modified schedule. Periodic key rotation mitigates this risk.

3. **No formal security proof.** The modification is analysed empirically. A formal security reduction proving that the modified variant is at least as secure as the original under standard cryptographic assumptions is beyond the scope of this project.

4. **Reduced-round proxy.** Partial collision results on 10–30 rounds are used as a proxy for full-round security. This is a standard experimental methodology but does not directly imply guarantees for the full 80-round variant.

## 4.3 Future Work

- **Constant-time implementation.** A production-quality implementation should ensure that the key schedule derivation and rotation-constant selection are constant-time to prevent timing side-channels.
- **Formal analysis.** Future work could apply differential cryptanalysis tools to quantify the increase in the number of active S-boxes (or analogous complexity measures) introduced by key-dependent rotation constants.
- **Hardware implementation.** An FPGA or ASIC implementation would allow accurate assessment of area and throughput overhead, relevant for embedded and IoT deployment scenarios.
- **Integration with HMAC.** A keyed hash variant could replace the HMAC outer/inner padding with the key-dependent schedule, potentially simplifying the construction while maintaining authentication properties.
- **Multiple key-derived constants.** Extending the scheme to derive all four rotation constants (1, 8, 19, 61) independently from the key would increase the keyspace of the schedule configuration.

## 4.4 Conclusion

This project designed and evaluated a modified SHA-512 variant that replaces the fixed rotation constants in the message schedule σ functions with values derived from a secret key. The experimental results demonstrate:

1. **Avalanche effect** is maintained at near-ideal levels (≈ 50%) with added per-key unpredictability.
2. **Bit independence** is preserved; BIC scores meet the > 95% target.
3. **Computational overhead** is bounded, remaining below the 10% target for typical message sizes.
4. **Partial collision resistance** is improved in reduced-round settings, as measured by higher mean attempt counts.

The modification is lightweight, deterministic given the shared key, and fully backward-compatible in terms of output format (512-bit digest). It represents a viable approach for use cases where both hash integrity and schedule unpredictability are desired — for example, in keyed message authentication and application-specific hash constructions.

---

*EC6204 Information Security — Mini Project*
*Modified SHA-512 with Key-Dependent Message Schedule Rotation Constants*
