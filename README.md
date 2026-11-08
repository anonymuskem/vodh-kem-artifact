
# VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification

**Reference implementation and experimental artifact for an accepted IEEE Access research paper (2026).**

VODH-KEM is a hybrid Key Encapsulation Mechanism (KEM) that combines RSA-OAEP and ElGamal encryption with verifiable ordering, cross-verification, and ciphertext-bound session-key derivation.

The project explores a structural approach to hybrid cryptography, focusing on the simultaneous use of two public-key primitives, consistency verification, and the behavior of the construction under Single-Assumption Failure (SAF).

> **Research implementation:** This repository is intended for academic evaluation and reproducibility. It has not undergone an independent cryptographic security audit and should not be used in production systems.

---

## Publication

**Title:** VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification

**Authors:** Missaoui Mohammed El Amine and Qian Weizhong

**Journal:** IEEE Access

**Status:** Accepted (2026)

**DOI:** To be added following official publication.

The repository contains the C/OpenSSL implementation, historical Python prototypes, experimental data, and generated figures associated with the research.

---

## Overview

VODH-KEM uses two public-key encryption primitives to protect the same randomly generated seed:

- **RSA-OAEP:** Encrypts the encapsulated seed using RSA.
- **ElGamal:** Independently encrypts the same seed over a finite-field group.
- **VRF-based ordering:** Provides a verifiable commitment to the composition order.
- **Cross-verification:** Checks that both ciphertext components decrypt to the same seed.
- **Hash binding:** Derives the session key from the recovered seed and ciphertext components.

The session-key derivation is specified as:

```text
K = SHA-256(K_raw || C1 || C2 || b)
```

where:

- `K_raw` is the randomly generated 256-bit seed.
- `C1` and `C2` are the ciphertext components.
- `b` is the VRF-derived ordering bit.

### Security scope

The accepted paper establishes an IND-CCA2 security reduction in the Random Oracle Model relative to an explicit **Dual-Seed One-Wayness (DS-OW)** assumption.

It also establishes a restricted DS-OW result based on RSA-OAEP and the Decisional Diffie-Hellman (DDH) assumption when no decapsulation queries are available.

The chosen-ciphertext case remains an explicit assumption; it is not proved solely from RSA-OAEP and DDH.

**Important limitations:**

- VODH-KEM is not an OR-secure KEM combiner.
- Breaking either underlying encryption component compromises session-key confidentiality.
- The SAF analysis concerns residual structural properties, particularly ciphertext consistency.
- Ciphertext consistency does not mean that fresh valid ciphertexts cannot be generated.
- VRF pseudorandomness is not required for the IND-CCA2-to-DS-OW reduction.
- The construction is not post-quantum secure.

The complete security analysis and assumptions are presented in Section VII of the paper.

---

## Repository Structure

```text
vodh-kem-artifact/
|
|-- README.md
|
|-- Source/
|   |-- main.c
|   |-- main.exe
|   |-- vodh_plots_c.py
|   |-- prototype.py
|   |-- prototype_Compa.py
|   |-- vodh_results.json
|   `-- vodh_comparison_results.json
|
`-- Results/
    |-- Json_Results/
    |   `-- vodh_c_results_3072.json
    |
    `-- Images/
        |-- fig1_timing_comparison_c_3072.png
        |-- fig2_per_run_c_3072.png
        |-- ...
        `-- fig11_dashboard_c_3072.png
```

### Main files

| File | Description |
|---|---|
| `Source/main.c` | Primary C/OpenSSL implementation, verification tests, and comparative benchmarks |
| `Source/vodh_plots_c.py` | Python script used to generate experimental visualizations |
| `Results/Json_Results/vodh_c_results_3072.json` | Recorded benchmark results for 3072-bit parameters |
| `Results/Images/` | Experimental plots generated from the recorded results |
| `Source/prototype.py` | Earlier Python prototype used during development |
| `Source/prototype_Compa.py` | Historical Python comparison experiments |
| `Source/main.exe` | Precompiled Windows executable included in the original repository |

The Python prototypes represent earlier development stages and should not be considered equivalent to the final C implementation.

---

## Requirements

### C Implementation

- GCC or another compatible C compiler
- OpenSSL 3.x with development headers
- A Linux, Windows, or macOS development environment

The experimental environment reported in the paper was:

| Component | Configuration |
|---|---|
| Operating system | Windows 11 (AMD64) |
| Compiler | GCC 14.2 |
| Cryptographic library | OpenSSL 3.6.1 |
| RSA modulus | 3072 bits |
| ElGamal group | RFC 3526 Group 15 |
| Benchmark iterations | 50 per scheme |

### Python Visualization

The plotting script requires:

```bash
python -m pip install numpy scipy matplotlib
```

---

## Compilation and Execution

Run the following commands from the repository root.

### Windows (MSYS2 MinGW x64)

Install the required packages:

```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```

Compile:

```bash
gcc -O2 -Wno-deprecated-declarations -o vodh_kem.exe Source/main.c -lssl -lcrypto -lm
```

Run:

```bash
./vodh_kem.exe
```

### Linux (Ubuntu/Debian)

Install dependencies:

```bash
sudo apt-get update
sudo apt-get install -y gcc libssl-dev
```

Compile:

```bash
gcc -O2 -Wno-deprecated-declarations -o vodh_kem Source/main.c -lssl -lcrypto -lm
```

Run:

```bash
./vodh_kem
```

### macOS (Homebrew)

Install OpenSSL:

```bash
brew install openssl
```

Compile:

```bash
gcc -O2 -Wno-deprecated-declarations -o vodh_kem Source/main.c \
  -I"$(brew --prefix openssl)/include" \
  -L"$(brew --prefix openssl)/lib" \
  -lssl -lcrypto -lm
```

Run:

```bash
./vodh_kem
```

The C program runs its verification tests and experimental benchmarks and generates a `vodh_c_results.json` file in the current working directory.

The executable was successfully compiled and executed in a separate Linux test environment. Performance measurements may differ depending on the platform, processor, OpenSSL version, and compiler configuration.

---

## Experimental Results

The accepted manuscript reports performance measurements using 3072-bit parameters and 50 runs per scheme.

### VODH-KEM Performance

| Operation | Mean (ms) | Standard Deviation (ms) |
|---|---:|---:|
| Key Generation | 193.58 | 112.21 |
| Encapsulation | 12.40 | 0.53 |
| Decapsulation | 15.18 | 0.48 |
| Total Encapsulation + Decapsulation | 27.58 | — |

The paper reports approximately **1.09× total encapsulation and decapsulation latency** relative to the ElGamal baseline.

The archived JSON contains the recorded measurements. Numerical results from a new execution may differ from the original experimental environment.

---

## Generating Figures

The repository includes a plotting script that generates 11 figures from the recorded benchmark data.

Install the dependencies:

```bash
python -m pip install numpy scipy matplotlib
```

Generate the figures:

```bash
python Source/vodh_plots_c.py
```

The script reads:

```text
Results/Json_Results/vodh_c_results_3072.json
```

and writes its figures to:

```text
Results/Images/
```

The generated visualizations include timing comparisons, per-run measurements, performance distributions, ciphertext-size comparisons, and verification-test summaries.

To regenerate figures using new measurements, preserve the original JSON before replacing the plotting input.

---

## Implementation Verification

The accepted paper reports nine verification checks:

| Test | Description |
|---|---|
| T1 | Encapsulation and decapsulation correctness |
| T2 | VRF determinism |
| T3 | Valid VRF proof acceptance |
| T4 | Invalid proof rejection with a different public key |
| T5 | Tampered ciphertext rejection |
| T6 | Incorrect private-key rejection |
| T7 | RSA/ElGamal parameter independence |
| T8 | Different-input VRF output distinctness |
| T9 | Public-key-only VRF verification |

**Reported result:** 9/9 tests passed in the experimental evaluation.

### Implementation notes

The available C source predates some of the final manuscript revisions:

- The source still contains a legacy SHA-512 hash-bridge routine and labels T7 as hash-bridge sensitivity. The accepted paper instead specifies independent fixed ElGamal group parameters and describes T7 as parameter independence.
- The source describes its VRF routine as a simplified ECVRF construction. Full conformance with RFC 9381 has not been independently established.
- The implementation's serialization and some commitment inputs require reconciliation with the final pseudocode.
- The JSON writer stores fixed per-test success flags rather than dynamically serializing each individual test result.

These differences are documented to distinguish the currently available research artifact from the final manuscript specification.

The verification tests demonstrate selected implementation behaviors; they do not replace formal security analysis or a cryptographic audit.

---

## Cryptographic Parameters

| Parameter | Paper Specification |
|---|---|
| RSA | RSA-OAEP, 3072-bit modulus |
| ElGamal | RFC 3526 Group 15, 3072-bit safe prime |
| ElGamal generator | 2 |
| VRF | ECVRF-P256-SHA256 |
| Encapsulated seed | 256 bits |
| Session-key derivation | SHA-256 ciphertext binding |
| RSA ciphertext size | 384 bytes |
| ElGamal ciphertext size | 768 bytes |
| Ordering bit | 1 byte |
| Total KEM encapsulation | 1153 bytes |

The accepted construction uses fixed ElGamal group parameters independent of the RSA modulus.

The 1153-byte value refers to the serialized core KEM encapsulation described in the paper, not necessarily the size of an implementation-specific C structure.

---

## Reproducibility and Limitations

This repository provides the implementation and recorded experimental results associated with the research.

For reproducibility:

1. Use the documented compiler and cryptographic library where possible.
2. Execute the C program and inspect the verification-test output.
3. Compare newly generated benchmark data against the archived JSON.
4. Regenerate figures using the provided Python script.
5. Consult the paper for formal definitions, assumptions, and security limitations.

The available implementation should be treated as a research prototype, not as a production-ready cryptographic library.

In particular, the accepted paper's security arguments are conditional on the stated assumptions, and a complete independent implementation audit has not been performed.

---

## Citation

If you use this repository or its experimental results in academic work, please cite:

**Missaoui Mohammed El Amine and Qian Weizhong.**  
"VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification."  
*IEEE Access*, accepted 2026.

The official IEEE DOI and publication details will be added when available.

---

## References

1. Bellare and Rogaway, *Optimal Asymmetric Encryption*, EUROCRYPT, 1994.
2. ElGamal, *A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms*, IEEE Transactions on Information Theory, 1985.
3. Dodis and Katz, hybrid KEM combiners, TCC, 2005.
4. Fujisaki and Okamoto, secure encryption transformations, CRYPTO, 1999.
5. Micali, Rabin, and Vadhan, *Verifiable Random Functions*, FOCS, 1999.
6. IETF RFC 9381, *Verifiable Random Functions (VRFs)*, 2023.
7. IETF RFC 3526, *More Modular Exponential (MODP) Diffie-Hellman Groups for Internet Key Exchange (IKE)*, 2003.
8. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.

---

## License

No software license has been declared for this repository. Reuse and redistribution are subject to applicable copyright permissions until the copyright holders select a license.
