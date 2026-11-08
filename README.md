# VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification

**Research artifact accompanying the accepted IEEE Access manuscript.**

VODH-KEM combines RSA-OAEP and ElGamal encryption of a shared 256-bit seed, a verifiable VRF-derived ordering commitment, cross-verification at decapsulation, and ciphertext-bound session-key derivation.

> **Research prototype, not production-ready cryptography.** The security results have explicitly stated assumptions and limitations. Do not use this implementation to protect real-world secrets or deploy it in TLS.

## Publication and artifact

**Paper:** *VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification*  
**Authors:** Missaoui Mohammed El Amine and Qian Weizhong  
**Journal:** IEEE Access (accepted; publication metadata pending)  
**Source artifact:** https://github.com/anonymuskem/vodh-kem-artifact

The manuscript cites this repository as the source for the C/OpenSSL implementation and benchmark artifacts. A final DOI and citation record can be added when IEEE assigns them. Do not substitute the manuscript's placeholder DOI.

## Security scope: read before using

The paper establishes a **Random Oracle Model (ROM) reduction of IND-CCA2 security to Dual-Seed One-Wayness (DS-OW)**. It proves DS-OW from RSA-OAEP IND-CPA security and the ElGamal/DDH assumption **only when the adversary has no decapsulation queries**. DS-OW with chosen-ciphertext queries is an **explicit assumption**, not a consequence proved from RSA-OAEP and DDH alone. See Theorems 1–2 and Remark 3.

- **Not an OR-combiner:** Breaking either underlying encryption component exposes the shared seed and therefore the derived session key. VODH-KEM does **not** retain session-key confidentiality under Single-Assumption Failure (SAF).
- **Ciphertext consistency:** Decapsulation checks that the two components decrypt to the same seed. The paper analyzes resistance to re-binding an existing challenge ciphertext component to a *different* seed. This is **not ciphertext unforgeability**: anyone with the public key can create fresh valid encapsulations.
- **VRF commitment:** ECVRF-P256-SHA256 commits to a verifiable ordering bit. VRF pseudorandomness is **not required** by the paper's IND-CCA2-to-DS-OW reduction; it is used in its separate order-bias analysis.
- **Hash binding:** The session key is derived from `SHA-256(K_raw || C1 || C2 || b)` after the consistency check. The paper describes this as *FO-style* hash binding, not a full Fujisaki–Okamoto transform.

## Repository contents

The current artifact is organized around the following files:

| File | Purpose |
| --- | --- |
| `main.c` | Primary C/OpenSSL reference implementation and experimental evaluation |
| `vodh_plots_c.py` | Generates figures from recorded benchmark results |
| `vodh_c_results_3072.json` | Recorded 3072-bit benchmark data (50 runs per scheme) |
| `prototype.py` | Historical Python prototype; uses an HMAC-based VRF approximation rather than the final ECVRF |
| `prototype_Compa.py` | Historical Python comparison benchmark at 2048 bits |
| `README.md` | Documentation and reproduction guidance |

The Python prototypes are retained for historical reference. **The C implementation and 3072-bit benchmark data are the primary artifacts for the accepted paper.** Results from the prototypes should not be represented as the final paper's results.

## Build and run

### Requirements

- C compiler (GCC; paper environment: GCC 14.2)
- OpenSSL 3.x with development headers (paper environment: OpenSSL 3.6.1)
- Python 3 with NumPy, SciPy, and Matplotlib for plotting

### Windows (MSYS2 MinGW x64)

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl

gcc -O2 -Wno-deprecated-declarations -o main.exe main.c -lssl -lcrypto -lm
./main.exe
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y gcc libssl-dev

gcc -O2 -Wno-deprecated-declarations -o vodh_kem main.c -lssl -lcrypto -lm
./vodh_kem
```

### macOS (Homebrew)

```bash
brew install openssl

gcc -O2 -Wno-deprecated-declarations -o vodh_kem main.c \
  -I"$(brew --prefix openssl)/include" \
  -L"$(brew --prefix openssl)/lib" \
  -lssl -lcrypto -lm

./vodh_kem
```

Build commands are provided for the existing single-file layout. The published measurements were collected on Windows 11 (AMD64), GCC 14.2, and OpenSSL 3.6.1. Different compiler, library, hardware, and operating-system versions may produce different timings. These cross-platform commands have not been independently verified here.

## Reproducing the benchmarks

The accepted paper reports 50 runs per scheme using 3072-bit parameters. Running the C executable performs the implementation's evaluation and writes benchmark results.

```bash
./vodh_kem
```

On Windows/MSYS2, use `./main.exe` instead.

If the executable writes `vodh_c_results.json`, preserve the recorded reference file and rename the newly generated output before plotting:

```bash
mv vodh_c_results.json vodh_c_results_3072.json
```

**Caution:** This command overwrites the filename used for the reference data. Save or commit the original JSON first if you want to compare a new run against the accepted paper.

### Generate figures

```bash
python -m pip install numpy scipy matplotlib
python vodh_plots_c.py
```

The plotting script is intended to read `vodh_c_results_3072.json` and generate the experimental figures. Check its input/output paths against the current script before running.

## Reported performance

The following values are from the accepted manuscript, not from a new benchmark run.

| Operation | VODH-KEM mean | Standard deviation |
| --- | ---: | ---: |
| Key generation | 193.58 ms | 112.21 ms |
| Encapsulation | 12.40 ms | 0.53 ms |
| Decapsulation | 15.18 ms | 0.48 ms |
| Encapsulation + decapsulation | 27.58 ms | — |

For comparison, the manuscript reports **25.2 ms** total encapsulation-plus-decapsulation time for ElGamal alone, versus **27.58 ms** for VODH-KEM: approximately **1.09×** the ElGamal baseline.

These measurements are environment-specific. The manuscript reports nine passing implementation verification tests; passing tests do not substitute for a formal security proof or independent security audit.

## Cryptographic parameters

| Parameter | Configuration |
| --- | --- |
| RSA-OAEP modulus | 3072 bits |
| ElGamal group | RFC 3526 Group 15, fixed 3072-bit safe prime |
| ElGamal generator | 2 |
| Encapsulated seed | 256 bits |
| VRF | ECVRF-P256-SHA256 (RFC 9381) |
| VRF commitment input | SHA-256 of encoded public parameters |
| Session-key derivation | SHA-256 over seed, both ciphertext components, and order bit |
| RSA ciphertext | 384 bytes |
| ElGamal ciphertext | 768 bytes |
| Order bit serialization | 1 byte |
| Total encapsulation size | 1153 bytes |

The ElGamal group is **not derived from the RSA modulus**. This is a deliberate correction from the earlier hash-bridge design.

## Implementation verification

The accepted paper reports all nine tests passing:

| Test | Verification |
| --- | --- |
| T1 | Encapsulation/decapsulation correctness |
| T2 | VRF determinism |
| T3 | Valid VRF proof acceptance |
| T4 | Wrong-key VRF proof rejection |
| T5 | Tampered ciphertext rejection |
| T6 | Wrong private-key rejection |
| T7 | RSA/ElGamal parameter independence |
| T8 | VRF output distinctness for different inputs |
| T9 | VRF verification using only the public key |

These are implementation checks, not empirical proofs of IND-CCA2 security.

## Limitations

- **Explicit DS-OW assumption:** The chosen-ciphertext version of DS-OW is assumed rather than reduced to RSA-OAEP and DDH alone.
- **No single-assumption-failure confidentiality:** Compromise of either underlying encryption component exposes the encapsulated seed.
- **No post-quantum security:** Both RSA and finite-field ElGamal are vulnerable to sufficiently capable quantum computers.
- **Not a production TLS integration:** The paper discusses protocol integration, but this repository does not establish a standards-compliant, production-ready TLS deployment.
- **Implementation considerations:** The manuscript identifies engineering limitations, including its ECVRF hash-to-curve approach and single-machine timing evaluation.

See Sections VII and XI of the accepted manuscript for the precise scope of the security analysis and limitations.

## Citation

If you use this artifact, please cite:

Missaoui Mohammed El Amine and Qian Weizhong, **“VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification,”** *IEEE Access*, accepted, 2026. DOI pending.

The final IEEE DOI, volume, pages, and publication date should be added after they are assigned.

## References

- Bellare and Rogaway, *Optimal Asymmetric Encryption*, EUROCRYPT 1994.
- ElGamal, *A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms*, IEEE Transactions on Information Theory, 1985.
- Dodis and Katz, work on hybrid KEM combiners, TCC 2005.
- Fujisaki and Okamoto, work on secure encryption transformations, CRYPTO 1999.
- Micali, Rabin, and Vadhan, *Verifiable Random Functions*, FOCS 1999.
- IETF RFC 9381, *Verifiable Random Functions (VRFs)*.
- IETF RFC 3526, *More Modular Exponential (MODP) Diffie-Hellman Groups for Internet Key Exchange (IKE)*.
- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*.

## License

No software license is specified in this README. Until a license is added, do not assume the repository grants permission for unrestricted redistribution or reuse. A license should be selected by the copyright holders before public reuse is encouraged.
