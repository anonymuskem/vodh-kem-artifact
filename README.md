
# VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification

**Reference implementation and experimental artifact accompanying an accepted IEEE Access paper (2026).**

VODH-KEM is a research-oriented hybrid Key Encapsulation Mechanism (KEM) combining RSA-OAEP and ElGamal encryption with a Verifiable Random Function (VRF)-based ordering commitment, cross-verification, and ciphertext-bound session-key derivation.

The project investigates a structural approach to hybrid cryptography, emphasizing verifiable composition, ciphertext consistency, and the behavior of dual-primitive constructions under Single-Assumption Failure (SAF).

> **Research software notice:** This repository provides a research prototype and experimental artifacts. It is not a production-ready cryptographic library and has not undergone an independent implementation security audit.

---

## Publication

**Title:** VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification

**Authors:** Missaoui Mohammed El Amine and Qian Weizhong

**Journal:** IEEE Access

**Status:** Accepted, 2026

**DOI:** Pending official publication.

This repository contains source code, experimental measurements, and generated figures associated with the research. Publication metadata will be updated when the article becomes available through IEEE Xplore.

---

## Overview

VODH-KEM combines two classical public-key encryption primitives:

- **RSA-OAEP:** Encrypts a randomly generated seed.
- **ElGamal:** Encrypts the same seed using an independent finite-field public key.
- **VRF ordering commitment:** Provides a publicly verifiable commitment to the ordering bit.
- **Cross-verification:** Checks whether both ciphertext components decrypt to the same seed.
- **Hash binding:** Derives the session key from the seed and complete encapsulation.

The accepted paper specifies the following session-key derivation:

```text
K = SHA-256(K_raw || C1 || C2 || b)
```

where `K_raw` is the 256-bit encapsulated seed, `C1` and `C2` are the two ciphertext components, and `b` is the VRF-derived ordering bit.

### Security scope

The paper establishes a Random Oracle Model (ROM) reduction of IND-CCA2 security to an explicit **Dual-Seed One-Wayness (DS-OW)** assumption.

It further establishes DS-OW under RSA-OAEP IND-CPA security and the Decisional Diffie-Hellman (DDH) assumption in the restricted setting without decapsulation queries. The chosen-ciphertext case of DS-OW remains an explicit assumption rather than a result derived solely from RSA-OAEP and DDH.

The Single-Assumption Failure (SAF) framework is used as an analytical perspective, not as a new competing security notion.

Important limitations:

- VODH-KEM is not an OR-secure KEM combiner.
- Session-key confidentiality is not preserved when either underlying encryption component is broken.
- Cross-verification enforces ciphertext consistency, but does not prevent fresh valid encapsulations.
- VRF pseudorandomness is not required for the paper's IND-CCA2-to-DS-OW reduction.
- The construction does not provide post-quantum security.

For formal definitions, assumptions, proofs, and limitations, refer to Sections III, VII, and XI of the accepted manuscript.

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

### File descriptions

| File | Description |
|---|---|
| `Source/main.c` | Primary C/OpenSSL research implementation, verification tests, and benchmarks |
| `Source/main.exe` | Precompiled Windows executable from the original project |
| `Source/vodh_plots_c.py` | Python script for generating 11 experimental figures |
| `Source/prototype.py` | Historical Python prototype from the initial development stage |
| `Source/prototype_Compa.py` | Historical Python comparison experiments |
| `Source/vodh_results.json` | Results associated with earlier Python experiments |
| `Source/vodh_comparison_results.json` | Historical comparison results |
| `Results/Json_Results/vodh_c_results_3072.json` | Archived C/OpenSSL benchmark data for 3072-bit parameters |
| `Results/Images/` | Generated experimental figures |

The primary artifact is the C/OpenSSL implementation. The Python prototypes are retained as historical development references and do not necessarily implement the final manuscript construction.

---

## Requirements

### C implementation

- GCC or another compatible C compiler
- OpenSSL 3.x, including development headers
- Windows, Linux, or macOS

### Experimental environment reported in the paper

| Component | Configuration |
|---|---|
| Operating system | Windows 11 (AMD64) |
| Compiler | GCC 14.2 |
| Cryptographic library | OpenSSL 3.6.1 |
| RSA key size | 3072 bits |
| ElGamal group | RFC 3526 Group 15 (3072-bit) |
| Benchmark repetitions | 50 per scheme |

### Python plotting dependencies

- Python 3
- NumPy
- SciPy
- Matplotlib

Install the plotting dependencies using:

```bash
python -m pip install numpy scipy matplotlib
```

---

## Compilation and Execution

The following commands should be run from the repository root.

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

Install the dependencies:

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

The executable performs the implementation's verification checks and comparative benchmarks, and writes a JSON results file named `vodh_c_results.json` to the current working directory.

The uploaded C implementation was compiled and executed successfully during a separate Linux artifact check. Timing measurements may differ depending on the hardware, operating system, compiler, and OpenSSL version.

---

## Experimental Results

The accepted paper reports the following measurements for 3072-bit parameters, using 50 benchmark runs per scheme.

### VODH-KEM performance

| Operation | Mean (ms) | Standard deviation (ms) |
|---|---:|---:|
| Key generation | 193.58 | 112.21 |
| Encapsulation | 12.40 | 0.53 |
| Decapsulation | 15.18 | 0.48 |
| Total Encapsulation + Decapsulation | 27.58 | — |

The paper reports approximately **1.09× total encapsulation and decapsulation latency** relative to the ElGamal baseline.

The archived JSON contains the original recorded experimental measurements. New executions may produce different timing results.

### Benchmark data

The archived benchmark data can be found at:

```text
Results/Json_Results/vodh_c_results_3072.json
```

The archived JSON provides the underlying measurements and comparative data used by the plotting script.

The original JSON should be preserved when generating new experiments. Note that the archived ElGamal baseline mean differs slightly from the rounded comparison reported in the manuscript.

---

## Generating Figures

The repository contains a Python script that generates 11 experimental figures.

Install the plotting dependencies:

```bash
python -m pip install numpy scipy matplotlib
```

Run the plotting script from the repository root:

```bash
python Source/vodh_plots_c.py
```

By default, the script reads:

```text
Results/Json_Results/vodh_c_results_3072.json
```

and saves generated figures in:

```text
Results/Images/
```

The figures include performance comparisons, timing distributions, per-run measurements, ciphertext-size comparisons, and implementation verification summaries.

Regeneration of the figures from the archived data was checked successfully during the artifact review.

---

## Implementation Verification

The accepted paper reports nine implementation verification tests:

| Test | Description |
|---|---|
| T1 | Encapsulation and decapsulation correctness |
| T2 | VRF determinism |
| T3 | VRF proof validity |
| T4 | Invalid VRF proof rejection using a different public key |
| T5 | Tampered ciphertext rejection |
| T6 | Incorrect private-key rejection |
| T7 | RSA/ElGamal parameter independence |
| T8 | Distinct VRF outputs for different inputs |
| T9 | Public-key-only VRF proof verification |

**Reported result in the accepted manuscript: 9/9 verification tests passed.**

These tests assess selected implementation behaviors and do not constitute an independent proof of cryptographic security.

---

## Cryptographic Parameters

The following table summarizes the construction specified in the accepted manuscript.

| Parameter | Paper specification |
|---|---|
| RSA encryption | RSA-OAEP |
| RSA modulus | 3072 bits |
| ElGamal group | RFC 3526 Group 15 |
| ElGamal group size | 3072 bits |
| ElGamal generator | 2 |
| VRF | ECVRF-P256-SHA256 |
| Encapsulated seed | 256 bits |
| Session-key derivation | SHA-256 ciphertext binding |
| RSA ciphertext size | 384 bytes |
| ElGamal ciphertext size | 768 bytes |
| Ordering bit serialization | 1 byte |
| Total KEM encapsulation | 1153 bytes |

The accepted construction specifies a fixed ElGamal group that is independent of the RSA modulus.

---

## Implementation and Manuscript Alignment

This repository contains the research implementation developed and evaluated during the VODH-KEM project.

The accepted IEEE Access manuscript includes refinements to the formal construction and security analysis. Consequently, several details of the available source code differ from the final manuscript specification.

### Parameter generation

The C source retains legacy SHA-512 hash-bridge code associated with the RSA public parameters and the initialization of the random generator.

The accepted manuscript instead specifies an independent ElGamal group using the fixed RFC 3526 Group 15 parameters, without a hash-derived dependency on RSA parameters.

### Verification test T7

In the current C source, T7 checks hash-bridge sensitivity to changes in RSA public parameters.

In the accepted manuscript, T7 is described as checking parameter independence.

Therefore, the current implementation's nine passing tests should not be interpreted as an exact one-to-one reproduction of all nine final manuscript test definitions.

### VRF implementation

The C source contains a customized ECVRF-style implementation with publicly verifiable proofs.

The accepted manuscript specifies ECVRF-P256-SHA256 according to RFC 9381. Full conformance of the existing implementation with RFC 9381 has not been independently established.

### Commitment inputs and serialization

The source code and final manuscript pseudocode differ in aspects of the VRF commitment input and data serialization.

These details require reconciliation before the available implementation can be described as fully specification-equivalent.

### Artifact status

The source code, archived results, and figures are provided for research inspection and experimental reference.

The archived measurements are preserved as originally recorded. Correcting the implementation differences would require renewed verification and benchmarking; equivalent performance results have not been established for such a corrected implementation.

Accordingly, this repository should not be interpreted as an independently audited or fully specification-equivalent implementation of the final accepted construction.

---

## Reproducibility

To inspect and reproduce the available experimental artifact:

1. Compile `Source/main.c` using a compatible GCC and OpenSSL environment.
2. Execute the program and inspect its verification-test output.
3. Preserve the archived benchmark JSON before generating new measurements.
4. Compare new benchmark results against the archived data.
5. Execute `Source/vodh_plots_c.py` to regenerate the figures.
6. Refer to the accepted paper for the final construction, formal security statements, and limitations.

The archived data and current implementation are provided as research artifacts. Matching the final paper's cryptographic specification requires resolving the documented implementation differences.

---

## Limitations

VODH-KEM is an experimental cryptographic construction with explicit assumptions and limitations:

- The IND-CCA2 analysis depends on the DS-OW assumption in the chosen-ciphertext setting.
- The construction does not provide confidentiality under single-assumption failure.
- It is not an OR-secure hybrid combiner.
- It is not post-quantum secure.
- The current source has not been independently verified for full RFC 9381 conformance.
- The available source code is not fully aligned with all final manuscript specifications.
- Experimental timings are platform- and implementation-dependent.
- The repository does not establish production-ready TLS integration or formal implementation security.

Users should consult the accepted article before drawing conclusions about the security properties of the construction.

---

## Citation

If you use this work or its experimental artifacts, please cite:

**Missaoui Mohammed El Amine and Qian Weizhong.**  
"VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification."  
*IEEE Access*, accepted 2026.

The official DOI, volume, page information, and publication date will be added after IEEE publication.

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

No software license has been declared for this repository. Reuse and redistribution are subject to applicable copyright permissions until the copyright holders select a license.
