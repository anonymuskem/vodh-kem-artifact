# VODH-KEM: VRF-Ordered Dual-Hardness Key Encapsulation Mechanism

> **A hybrid public-key KEM combining RSA-OAEP and ElGamal with a Verifiable Random Function bridge for Single-Assumption-Failure (SAF) resilience.**

---

## 📄 Overview

VODH-KEM is a novel hybrid Key Encapsulation Mechanism that addresses the **Single-Assumption Failure (SAF)** threat model — the scenario where one classical hardness assumption (RSA or DDH) is broken while the other remains intact, as demonstrated by real-world attacks such as ROCA (2017) and Logjam (2015).

Unlike existing hybrid schemes that achieve security when **at least one** component is secure ("or" model), VODH-KEM requires an adversary to **simultaneously break both** RSA-OAEP and the DDH assumption ("and" model).

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
├── Mo_System.py                  # Python prototype (historical reference, HMAC-SHA256 VRF)
├── Mo_Sys_Compar.py              # Python comparison benchmark (historical reference)
├── vodh_c_results_3072.json      # Final benchmark results (50 runs, 3072-bit, C/OpenSSL)
└── README.md                     # This file
```

### File descriptions

| File | Description |
|---|---|
| `main.c` | Full C/OpenSSL 3.6.1 implementation. Includes VODH-KEM KeyGen, Encaps, Decaps, real ECVRF-P256-SHA256, ElGamal over RFC 3526 Group 15 (3072-bit), and all 9 security verification tests. Outputs benchmark results as JSON. |
| `vodh_plots_c.py` | Python script that reads `vodh_c_results_3072.json` and generates 11 publication-quality figures for the paper. |
| `Mo_System.py` | Original Python 3.11 prototype used for initial correctness validation. Uses HMAC-SHA256 as VRF approximation and 2048-bit keys. Kept for historical reference. |
| `Mo_Sys_Compar.py` | Python comparison benchmark (RSA-OAEP vs ElGamal vs Std. Hybrid vs VODH-KEM) at 2048-bit using the Python prototype. Kept for historical reference. |
| `vodh_c_results_3072.json` | Benchmark output from `main.exe` — 50 runs per scheme, 3072-bit keys, C/OpenSSL. Used by `vodh_plots_c.py` to generate figures. |

---

## ⚙️ Code Flow

```
STEP 1 — Compile C implementation
        main.c
           │
           ▼
        main.exe  (GCC + OpenSSL)

STEP 2 — Run benchmarks + security tests
        main.exe
           │
           ├── 9 Security Verification Tests (T1–T9)
           ├── Benchmark: RSA-OAEP  (50 runs)
           ├── Benchmark: ElGamal   (50 runs)
           ├── Benchmark: Std Hybrid (50 runs)
           └── Benchmark: VODH-KEM  (50 runs)
                    │
                    ▼
           vodh_c_results.json  (rename to vodh_c_results_3072.json)

STEP 3 — Generate figures
        vodh_plots_c.py
           │  reads: vodh_c_results_3072.json
           │
           └── Produces 11 figures:
               fig1_timing_comparison_c_3072.png
               fig2_per_run_c_3072.png
               fig3_boxplot_c_3072.png
               fig4_speedup_c_3072.png
               fig5_ciphertext_size_c_3072.png
               fig6_overhead_ratio_c_3072.png
               fig7_security_checklist_c_3072.png
               fig8_radar_c_3072.png
               fig9_cumulative_c_3072.png
               fig10_security_tests_c_3072.png
               fig11_dashboard_c_3072.png
```

---

## 🔧 Compilation & Running

### Requirements
- GCC 14+ (MinGW-w64 on Windows, or native on Linux/macOS)
- OpenSSL 3.x (with development headers)

---

### Windows (MSYS2 MinGW x64) — Recommended

**Step 1 — Install MSYS2**
Download from: https://www.msys2.org and install.

**Step 2 — Install dependencies**
Open **MSYS2 MinGW x64** terminal and run:
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
```

**Step 3 — Compile**
```bash
cd /c/path/to/VODH_KEM_M/
gcc -O2 -Wno-deprecated-declarations -o main.exe main.c -lssl -lcrypto -lm
```

**Step 4 — Run**
```bash
./main.exe
```

---

### Linux / macOS

**Step 1 — Install dependencies**
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install gcc libssl-dev -y

# macOS
brew install openssl
```

**Step 2 — Compile**
```bash
# Linux
gcc -O2 -Wno-deprecated-declarations -o vodh_kem main.c -lssl -lcrypto -lm

# macOS
gcc -O2 -Wno-deprecated-declarations -o vodh_kem main.c \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto -lm
```

**Step 3 — Run**
```bash
./vodh_kem
```

---

## 📊 Generating the Figures

After running `main.exe`, rename the output:
```bash
mv vodh_c_results.json vodh_c_results_3072.json
```

Then install Python dependencies and run:
```bash
pip install matplotlib numpy scipy
python vodh_plots_c.py
```

This generates all 11 figures in the same directory.

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
  Session key     : AES-256-GCM (256-bit)
  Hash bridge     : SHA-512
  Runs            : 50 per operation per scheme
============================================================
[4] Security Verification Tests ...
    T1. Correctness (K_encaps == K_decaps)               : PASS
    T2. VRF determinism (same input => same beta)        : PASS
    T3. VRF proof valid (correct key)                    : PASS
    T4. VRF proof rejected (wrong public key)            : PASS
    T5. Tampered ciphertext rejected                     : PASS
    T6. Wrong private key rejected                       : PASS
    T7. Hash bridge sensitive to RSA params              : PASS
    T8. VRF different input => different beta            : PASS
    T9. ECVRF verifiable with public key only (no sk)    : PASS
...
  VODH-KEM (Ours)   KeyGen: ~186ms  Encaps: ~13ms  Decaps: ~16ms
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
| Session Key | AES-256-GCM (256-bit) |
| Hash Bridge | SHA-512 |
| Security Level | ≈126.4 bits (effective) |

---

## 🛡️ Security Properties

| Property | VODH-KEM |
|---|---|
| Dual Hardness (Both Must Break) | ✅ |
| IND-CCA2 Security | ✅ |
| VRF-Verified Order | ✅ |
| Cross-Verify Integrity | ✅ |
| SAF Threat Model | ✅ |
| Protocol Ready (TLS 1.3) | ✅ |
| Real ECVRF (Verifiable) | ✅ |

---

## 📚 References

- Bellare & Rogaway, "Optimal Asymmetric Encryption — How to Encrypt with RSA," EUROCRYPT 1994
- ElGamal, "A Public Key Cryptosystem Based on Discrete Logarithms," IEEE Trans. Inf. Theory 1985
- Micali, Rabin, Vadhan, "Verifiable Random Functions," IEEE FOCS 1999
- Goldberg et al., "Verifiable Random Functions (VRFs)," IETF RFC 9381, 2023
- Kivinen & Kojo, "More MODP Diffie-Hellman Groups for IKE," IETF RFC 3526, 2003
- NIST, "Module-Lattice-Based KEM Standard," FIPS 203, 2024

---

## 📝 License

This code is provided for academic and research purposes.
