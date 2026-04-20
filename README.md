# VODH-KEM: VRF-Ordered Dual-Hardness Key Encapsulation Mechanism

> **A hybrid public-key KEM combining RSA-OAEP and ElGamal with a Verifiable Random Function bridge for Single-Assumption-Failure (SAF) resilience.**

> ⚠️ **Anonymous repository** — This repository supports an anonymous submission currently under peer review.

---

## ⚡ Quick Start

```bash
# Compile and run (Linux/macOS)
gcc -O2 -Wno-deprecated-declarations -o vodh_kem main.c -lssl -lcrypto -lm
./vodh_kem
```

Expected runtime: approximately 20–30 seconds on a modern machine (50 benchmark runs per scheme at 3072-bit keys).

---

## 📄 Overview

VODH-KEM is a hybrid Key Encapsulation Mechanism that addresses the **Single-Assumption Failure (SAF)** threat model — the scenario where one classical hardness assumption (RSA or DDH) is broken while the other remains intact, as demonstrated by real-world attacks such as ROCA (2017) and Logjam (2015).

Unlike existing hybrid schemes that achieve security when **at least one** component is secure ("or" model), VODH-KEM is designed to require an adversary to **simultaneously break both** RSA-OAEP and the DDH assumption ("and" model).

### Three core mechanisms:
1. **SHA-512 Hash Bridge** — one-way dependency between RSA and ElGamal key generation phases
2. **ECVRF-P256-SHA256 Order Commitment** — verifiably unpredictable composition ordering
3. **Cross-Verification Integrity** — implicit ciphertext authentication without a separate MAC

---

## 📁 Repository Structure

```
VODH_KEM_M/
│
├── main.c                        # Production C/OpenSSL implementation (PRIMARY)
├── vodh_plots_c.py               # Plot generator — reads JSON, produces 11 figures
├── prototype.py                  # Python prototype (historical reference, HMAC-SHA256 VRF)
├── prototype_Compa.py              # Python comparison benchmark (historical reference)
├── vodh_c_results_3072.json      # Final benchmark results (50 runs, 3072-bit, C/OpenSSL)
└── README.md                     # This file
```

### File descriptions

| File | Description |
|---|---|
| `main.c` | Full C/OpenSSL 3.6.1 implementation. Includes VODH-KEM KeyGen, Encaps, Decaps, real ECVRF-P256-SHA256, ElGamal over RFC 3526 Group 15 (3072-bit), and all 9 security verification tests. Outputs benchmark results as JSON. |
| `vodh_plots_c.py` | Python script that reads `vodh_c_results_3072.json` and generates 11 publication-quality figures. |
| `prototype.py` | Original Python 3.11 prototype used for initial correctness validation. Uses HMAC-SHA256 as VRF approximation and 2048-bit keys. Kept for historical reference. |
| `prototype_Compa.py` | Python comparison benchmark (RSA-OAEP vs ElGamal vs Std. Hybrid vs VODH-KEM) at 2048-bit. Kept for historical reference. |
| `vodh_c_results_3072.json` | Benchmark output from `main.exe` — 50 runs per scheme, 3072-bit keys, C/OpenSSL. Used by `vodh_plots_c.py` to generate figures. |

---

## 🔧 Compilation & Running

### Requirements
- GCC 14+ (MinGW-w64 on Windows, or native on Linux/macOS)
- OpenSSL 3.x (with development headers)

---

### Windows (MSYS2 MinGW x64) — Recommended

```bash
# Install dependencies
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl

# Compile
gcc -O2 -Wno-deprecated-declarations -o main.exe main.c -lssl -lcrypto -lm

# Run
./main.exe
```

### Linux

```bash
sudo apt-get install gcc libssl-dev -y
gcc -O2 -Wno-deprecated-declarations -o vodh_kem main.c -lssl -lcrypto -lm
./vodh_kem
```

### macOS

```bash
brew install openssl
gcc -O2 -Wno-deprecated-declarations -o vodh_kem main.c \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto -lm
./vodh_kem
```

---

> **Expected runtime:** approximately 20–30 seconds on a modern machine.
> Key generation is the slowest step (~186 ms per run due to safe prime search).

## 📊 Generating the Figures

```bash
mv vodh_c_results.json vodh_c_results_3072.json
pip install matplotlib numpy scipy
python vodh_plots_c.py
```

This generates all 11 figures used in the paper.

---

## 📋 Expected Output

```
============================================================
  VODH-KEM FULL EXPERIMENTAL EVALUATION (C / OpenSSL)
============================================================
  OpenSSL version : OpenSSL 3.6.x
  RSA key bits    : 3072
  ElGamal group   : RFC 3526 Group 15 (3072-bit safe prime)
  VRF             : ECVRF-P256-SHA256 (real proof, verifiable)
  Runs            : 50 per operation per scheme
============================================================
    T1. Correctness (K_encaps == K_decaps)               : PASS
    T2. VRF determinism (same input => same beta)        : PASS
    T3. VRF proof valid (correct key)                    : PASS
    T4. VRF proof rejected (wrong public key)            : PASS
    T5. Tampered ciphertext rejected                     : PASS
    T6. Wrong private key rejected                       : PASS
    T7. Hash bridge sensitive to RSA params              : PASS
    T8. VRF different input => different beta            : PASS
    T9. ECVRF verifiable with public key only (no sk)    : PASS
  Security tests : 9/9 passed
============================================================
```

---

## 🔑 Key Parameters

| Parameter | Value |
|---|---|
| RSA Key Size | 3072 bits |
| ElGamal Group | RFC 3526 Group 15 (3072-bit safe prime) |
| VRF | ECVRF-P256-SHA256 (RFC 9381) |
| Hash Bridge | SHA-512 |
| Security Level | ≈126.4 bits (effective) |

---

## 📚 References

- Bellare & Rogaway, EUROCRYPT 1994
- ElGamal, IEEE Trans. Inf. Theory 1985
- Micali, Rabin, Vadhan, IEEE FOCS 1999
- Goldberg et al., IETF RFC 9381, 2023
- Kivinen & Kojo, IETF RFC 3526, 2003
- NIST FIPS 203, 2024

---

## 📝 License

Provided for academic and research purposes. Author information will be disclosed upon paper acceptance.
