
# VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification

[![IEEE Access](https://img.shields.io/badge/IEEE%20Access-Published-blue)](https://doi.org/10.1109/ACCESS.2026.3752647)
[![DOI](https://img.shields.io/badge/DOI-10.1109%2FACCESS.2026.3752647-blue)](https://doi.org/10.1109/ACCESS.2026.3752647)
![Publication Year](https://img.shields.io/badge/Year-2026-green)
![Research Software](https://img.shields.io/badge/Software-Research%20Prototype-orange)

**Research implementation and experimental artifacts accompanying the IEEE Access publication.**

VODH-KEM is a hybrid Key Encapsulation Mechanism (KEM) that combines RSA-OAEP and ElGamal encryption with Verifiable Random Function (VRF)-based ordering, cross-verification, and ciphertext-bound session-key derivation.

The research investigates structural properties of dual-primitive cryptographic constructions, with particular attention to verifiable composition, ciphertext consistency, and Single-Assumption Failure (SAF).

> **Research software notice:** This repository contains a research prototype and experimental results. It is not a production-ready cryptographic library and has not undergone an independent implementation security audit.

---

## Publication

**Title:** VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification

**Authors:** Missaoui Mohammed El Amine and Qian Weizhong

**Journal:** IEEE Access

**Publisher:** IEEE

**Publication Year:** 2026

**Status:** Published online — Early Access

**DOI:** [10.1109/ACCESS.2026.3752647](https://doi.org/10.1109/ACCESS.2026.3752647)

**IEEE Xplore:** [View Published Article](https://ieeexplore.ieee.org/document/11789557)

The article is available through IEEE Xplore as an Open Access publication under a Creative Commons Attribution 4.0 (CC BY 4.0) license.

Early Access is an official, citable publication stage. Final bibliographic information may be updated by IEEE as production is completed.

---

## Overview

VODH-KEM combines two classical public-key encryption primitives:

- **RSA-OAEP:** Encrypts a randomly generated seed.
- **ElGamal:** Encrypts the same seed using a finite-field public key.
- **VRF ordering:** Provides a publicly verifiable commitment to the composition order.
- **Cross-verification:** Checks whether both ciphertext components decrypt to the same seed.
- **Hash binding:** Derives the session key from the seed and complete encapsulation.

The published construction specifies the following session-key derivation:

```text
K = SHA-256(K_raw || C1 || C2 || b)
```

where:

- `K_raw` is the 256-bit encapsulated seed.
- `C1` and `C2` are the ciphertext components.
- `b` is the VRF-derived ordering bit.

The combination of these mechanisms provides a verifiable dual-primitive construction with ciphertext-consistency checks.

### Security Scope

The paper establishes a Random Oracle Model (ROM) reduction of IND-CCA2 security to an explicit **Dual-Seed One-Wayness (DS-OW)** assumption.

It also establishes DS-OW under RSA-OAEP IND-CPA security and the Decisional Diffie-Hellman (DDH) assumption in the restricted setting without decapsulation queries.

The chosen-ciphertext case of DS-OW remains an explicit assumption rather than a result derived solely from RSA-OAEP and DDH.

The Single-Assumption Failure (SAF) framework is used as an analytical perspective for studying residual structural properties.

**Important limitations:**

- VODH-KEM is not an OR-secure KEM combiner.
- Session-key confidentiality is not preserved when either underlying encryption component is broken.
- Cross-verification enforces ciphertext consistency but does not prevent fresh valid encapsulations.
- VRF pseudorandomness is not required for the paper's IND-CCA2-to-DS-OW reduction.
- The construction does not provide post-quantum security.

For complete security definitions, proofs, and assumptions, refer to the [published article](https://doi.org/10.1109/ACCESS.2026.3752647).

---

## Repository Structure

```text
vodh-kem-artifact/
├── README.md
├── Source/
│   ├── main.c
│   ├── main.exe
│   ├── vodh_plots_c.py
│   ├── prototype.py
│   ├── prototype_Compa.py
│   ├── vodh_results.json
│   └── vodh_comparison_results.json
└── Results/
    ├── Json_Results/
    │   └── vodh_c_results_3072.json
    └── Images/
        ├── fig1_timing_comparison_c_3072.png
        ├── fig2_per_run_c_3072.png
        ├── ...
        └── fig11_dashboard_c_3072.png
```

### Main Files

| File | Description |
|---|---|
| `Source/main.c` | Primary C/OpenSSL research implementation, verification tests, and benchmarks |
| `Source/main.exe` | Precompiled Windows executable included in the original project |
| `Source/vodh_plots_c.py` | Python script generating 11 experimental figures |
| `Source/prototype.py` | Historical Python prototype used during initial development |
| `Source/prototype_Compa.py` | Historical Python comparison experiments |
| `Source/vodh_results.json` | Results from earlier Python experiments |
| `Source/vodh_comparison_results.json` | Historical comparison results |
| `Results/Json_Results/vodh_c_results_3072.json` | Archived C/OpenSSL benchmark measurements |
| `Results/Images/` | Generated experimental figures |

The C/OpenSSL implementation is the primary research artifact.

The Python prototypes are retained for historical reference and do not necessarily implement the final published construction.

---

## Requirements

### C Implementation

- GCC or another compatible C compiler
- OpenSSL 3.x with development headers
- Windows, Linux, or macOS

### Experimental Environment

The published paper reports the following environment:

| Component | Configuration |
|---|---|
| Operating System | Windows 11 (AMD64) |
| Compiler | GCC 14.2 |
| Cryptographic Library | OpenSSL 3.6.1 |
| RSA Key Size | 3072 bits |
| ElGamal Group | RFC 3526 Group 15 |
| Benchmark Runs | 50 per scheme |

### Python Dependencies

The plotting scripts require:

- Python 3
- NumPy
- SciPy
- Matplotlib

Install them using:

```bash
python -m pip install numpy scipy matplotlib
```

---

## Compilation and Execution

Run the following commands from the repository root.

### Windows (MSYS2 MinGW x64)

Install the required dependencies:

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

The executable runs the implementation's verification checks and comparative benchmarks.

Benchmark results are written to `vodh_c_results.json` in the current working directory.

The C implementation was previously compiled and executed successfully during an independent artifact-format check. This does not constitute an independent cryptographic security audit.

---

## Experimental Results

The published paper reports performance measurements using 3072-bit parameters and 50 benchmark runs per scheme.

### VODH-KEM Performance

| Operation | Mean (ms) | Standard Deviation (ms) |
|---|---:|---:|
| Key Generation | 193.58 | 112.21 |
| Encapsulation | 12.40 | 0.53 |
| Decapsulation | 15.18 | 0.48 |
| Total Encapsulation + Decapsulation | 27.58 | — |

The paper reports approximately **1.09× total encapsulation and decapsulation latency** relative to its ElGamal baseline.

These results represent measurements reported in the published article, not a guarantee of identical performance across hardware platforms.

### Archived Benchmark Data

The original benchmark measurements are available at:

```text
Results/Json_Results/vodh_c_results_3072.json
```

The archived JSON contains the measurements used for experimental analysis and visualization.

The archived ElGamal baseline mean differs slightly from the rounded value reported in the published manuscript. Preserve the original data when reproducing experiments.

---

## Generating Figures

The repository provides a Python script for generating 11 experimental figures.

Install dependencies:

```bash
python -m pip install numpy scipy matplotlib
```

Generate the figures:

```bash
python Source/vodh_plots_c.py
```

The plotting script reads:

```text
Results/Json_Results/vodh_c_results_3072.json
```

and produces figures in:

```text
Results/Images/
```

These include timing comparisons, per-run measurements, performance distributions, ciphertext-size comparisons, and verification summaries.

Figure generation using the archived data was previously checked successfully.

---

## Implementation Verification

The published paper reports nine implementation verification tests:

| Test | Description |
|---|---|
| T1 | Encapsulation and decapsulation correctness |
| T2 | VRF determinism |
| T3 | Valid VRF proof acceptance |
| T4 | Invalid VRF proof rejection under a different public key |
| T5 | Tampered ciphertext rejection |
| T6 | Incorrect private-key rejection |
| T7 | RSA/ElGamal parameter independence |
| T8 | Different-input VRF output distinctness |
| T9 | Public-key-only VRF verification |

**Published experimental result: 9/9 verification tests passed.**

These tests assess selected implementation behaviors. They do not constitute an independent proof of cryptographic security.

---

## Cryptographic Parameters

The following parameters describe the construction specified in the published paper.

| Parameter | Specification |
|---|---|
| RSA Encryption | RSA-OAEP |
| RSA Modulus | 3072 bits |
| ElGamal Group | RFC 3526 Group 15 |
| ElGamal Group Size | 3072 bits |
| ElGamal Generator | 2 |
| VRF | ECVRF-P256-SHA256 |
| Encapsulated Seed | 256 bits |
| Session-Key Derivation | SHA-256 ciphertext binding |
| RSA Ciphertext | 384 bytes |
| ElGamal Ciphertext | 768 bytes |
| Ordering Bit | 1 byte |
| Total KEM Encapsulation | 1153 bytes |

The published construction specifies fixed ElGamal group parameters independent of the RSA modulus.

---

## Implementation and Manuscript Alignment

This repository preserves the research implementation and experimental artifacts developed during the VODH-KEM project.

The final IEEE Access publication includes refinements to the formal construction and security analysis. Some details in the available source code therefore differ from the published specification.

### Parameter Generation

The C source retains legacy SHA-512 hash-bridge logic related to RSA public parameters and random-generator initialization.

The published construction instead specifies a fixed RFC 3526 Group 15 ElGamal group independent of RSA parameters.

### Verification Test T7

The available C implementation labels T7 as a test of hash-bridge sensitivity.

The published article describes T7 as a parameter-independence test.

Accordingly, the implementation's test output should not be interpreted as an exact one-to-one reproduction of every test definition in the final paper.

### VRF Implementation

The C source contains a customized ECVRF-style implementation with publicly verifiable proofs.

The published construction specifies ECVRF-P256-SHA256. Full RFC 9381 conformance of the available source code has not been independently established.

### Commitment Inputs and Serialization

Some VRF commitment inputs and data-serialization details differ between the source code and final published pseudocode.

Further verification is required before the implementation can be described as fully specification-equivalent.

### Artifact Status

The existing code, archived data, and figures are provided for academic inspection and experimental reference.

The original experimental results have been preserved. Correcting implementation differences would require renewed testing and benchmarking.

The repository should not be interpreted as an independently audited or fully specification-equivalent implementation of the published construction.

---

## Reproducibility

To inspect and reproduce the available experimental artifact:

1. Compile `Source/main.c` using a compatible GCC and OpenSSL environment.
2. Execute the program and inspect the verification results.
3. Preserve the archived benchmark JSON before running new experiments.
4. Compare new benchmark measurements with the original data.
5. Regenerate the experimental figures using `Source/vodh_plots_c.py`.
6. Refer to the published IEEE Access paper for formal specifications and security assumptions.

Experimental results may vary with hardware, operating system, compiler, and cryptographic library versions.

---

## Limitations

VODH-KEM is an experimental cryptographic construction.

Its documented limitations include:

- IND-CCA2 security is established relative to the explicit DS-OW assumption.
- The chosen-ciphertext DS-OW case is not derived solely from RSA-OAEP and DDH.
- Session-key confidentiality is not preserved under single-assumption failure.
- The scheme is not an OR-secure KEM combiner.
- The construction is not post-quantum secure.
- The current source has not been independently verified for full RFC 9381 conformance.
- The available implementation differs in certain details from the published specification.
- Experimental performance measurements depend on the execution environment.
- Production-ready TLS integration and formal implementation security have not been established.

For the complete theoretical treatment, refer to the [IEEE Access publication](https://doi.org/10.1109/ACCESS.2026.3752647).

---

## Citation

If you use VODH-KEM or its experimental artifacts in your research, please cite the published article.

### IEEE Style

M. M. El Amine and Q. Weizhong, "VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification," *IEEE Access*, 2026, doi: 10.1109/ACCESS.2026.3752647.

### BibTeX

```bibtex
@article{missaoui2026vodhkem,
  author  = {Missaoui Mohammed El Amine and Qian Weizhong},
  title   = {VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification},
  journal = {IEEE Access},
  year    = {2026},
  doi     = {10.1109/ACCESS.2026.3752647},
  url     = {https://doi.org/10.1109/ACCESS.2026.3752647}
}
```

For IEEE's preferred bibliographic formatting and the most recent publication metadata, use the **Cite This** option on the [IEEE Xplore article page](https://ieeexplore.ieee.org/document/11789557).

---

## References

1. Bellare and Rogaway, *Optimal Asymmetric Encryption*, EUROCRYPT, 1994.
2. ElGamal, *A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms*, IEEE Transactions on Information Theory, 1985.
3. Dodis and Katz, research on hybrid KEM combiners, TCC, 2005.
4. Fujisaki and Okamoto, research on secure encryption transformations, CRYPTO, 1999.
5. Micali, Rabin, and Vadhan, *Verifiable Random Functions*, FOCS, 1999.
6. IETF RFC 9381, *Verifiable Random Functions (VRFs)*, 2023.
7. IETF RFC 3526, *More Modular Exponential (MODP) Diffie-Hellman Groups for Internet Key Exchange (IKE)*, 2003.
8. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.

---

## License

The published IEEE Access article is distributed under the **Creative Commons Attribution 4.0 (CC BY 4.0)** license.

This article license does not automatically establish a software license for the GitHub repository.

No separate software license has currently been declared for the source code. Reuse and redistribution of the software remain subject to applicable copyright permissions until the copyright holders select a license.

---

## Acknowledgment

We acknowledge the peer-review and publication process of IEEE Access and the contributions of the research community to the foundational cryptographic techniques examined in this work.

---

**Published in IEEE Access (2026)**

**DOI:** https://doi.org/10.1109/ACCESS.2026.3752647
