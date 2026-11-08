VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification
Research artifact accompanying an accepted IEEE Access paper (2026). 
Authors: Missaoui Mohammed El Amine and Qian Weizhong 
Article:  VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification 
Repository: https://github.com/anonymuskem/vodh-kem-artifact
 DOI:Pending official IEEE publication metadata. The DOI in the author manuscript is a placeholder.
Research code; not audited for production use. This repository contains the uploaded artifact examined in November 2026. The included docs/ARTIFACT_AUDIT.md records differences between the current code and the accepted manuscript. Do not describe this particular source version as an exact implementation of every statement in the accepted paper until those discrepancies have been resolved.

Summary and security scope
VODH-KEM combines RSA-OAEP and finite-field ElGamal encryption of the same seed, cross-verifies the decrypted values, derives the output key from the seed and ciphertext, and attaches a verifiable order commitment.

The paper shows an IND-CCA2 reduction in the random-oracle model relative to the explicit Dual-Seed One-Wayness (DS-OW) assumption . It proves a no-decapsulation-query instance of DS-OW from RSA-OAEP and DDH; it does not establish the chosen-ciphertext instance directly from those primitive assumptions. VODH-KEM does not preserve session-key confidentiality when either underlying encryption component is broken. Its stated ciphertext-consistency property is narrower than ciphertext unforgeability. The VRF supports the order commitment; VRF pseudorandomness is not required for the paper's IND-CCA2-to-DS-OW reduction.

Implementation discrepancy: The code in Source/main.c still derives a SHA-512 hash of RSA parameters and adds it to OpenSSL's randomness before ElGamal key generation. The accepted manuscript instead specifies a fixed 3072-bit ElGamal group independent of RSA without a hash-derived dependency. The fixed prime itself is present in the code, but this legacy entropy-mixing step and its T7 test have not yet been updated. The code also describes its VRF as a simplified ECVRF construction; it has not been verified for RFC 9381 conformance. See the audit file.
Layout
Source/
  main.c                      C/OpenSSL experiment and reference prototype
  vodh_plots_c.py             Plot generator (reads archived JSON)
  prototype.py                Historical Python prototype
  prototype_Compa.py          Historical Python comparison
  vodh_results.json           Historical Python results
  vodh_comparison_results.json  Historical comparison results
Results/
  Json_Results/
    vodh_c_results_3072.json  Archived 50-run measurements
  Images/                     11 generated figures
docs/
  ARTIFACT_AUDIT.md           Verification results and known gaps
requirements-plot.txt
README.md
The Python prototypes are historical and not the primary C/OpenSSL artifact for the paper.
Build
The paper's experimental environment was Windows 11 (AMD64), GCC 14.2, OpenSSL 3.6.1 , at 3072-bit keys and 50 runs per scheme. A Linux compilation and execution were also checked independently with GCC 14.2 and OpenSSL 3.5.5 ; measurements are machine- and library-dependent.

From the root repository :
Linux (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y gcc libssl-dev
gcc -O2 -Wno-deprecated-declarations -o vodh_kem Source/main.c -lssl -lcrypto -lm
./vodh_kem
Windows (MSYS2 MinGW x64)
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
gcc -O2 -Wno-deprecated-declarations -o vodh_kem.exe Source/main.c -lssl -lcrypto -lm
./vodh_kem.exe
macOS (Homebrew)
brew install openssl
gcc -O2 -Wno-deprecated-declarations -o vodh_kem Source/main.c \
  -I"$(brew --prefix openssl)/include" \
  -L"$(brew --prefix openssl)/lib" -lssl -lcrypto -lm
./vodh_kem
The Windows and macOS commands have not been independently executed in this audit.

The executable runs the current implementation's verification tests and 50-run comparative benchmarks, then writes vodh_c_results.json into the current working directory . The program currently prints Hash bridge: SHA-512 and reports T7 as hash bridge sensitivity . These differ from the accepted manuscript's parameter-independence description. The JSON writer also hardcodes each of the nine individual test results as 1 ; use the terminal output for the observed per-test pass/fail status.
Archived measurements
The committed archived data is at Results/Json_Results/vodh_c_results_3072.json . Its 50 raw samples are internally consistent with the file's summary statistics. The paper reports:
Operation	VODH-KEM mean (ms)	Standard deviation (ms)
Key generation	193.58	112.21
Encapsulation	12.40	0.53
Decapsulation	15.18	0.48
Total encapsulation + decapsulation	27.58	—


For comparison, the paper gives 25.2 ms total for ElGamal, a roughly 1.09× ratio. The archived JSON instead records 24.88 ms for ElGamal (11.88+13.00 ms): another small inconsistency with the rounded paper table that should be documented rather than silently rewritten.
Generate plots
python -m pip install -r requirements-plot.txt
python Source/vodh_plots_c.py
The script reads Results/Json_Results/vodh_c_results_3072.json and writes its 11 figure files to Results/Images/ . This operation was successfully checked on Linux.

To plot a new benchmark run, copy its JSON file into the archived results location only after backing up the paper's original dataset , then rerun the plotting script:
cp Results/Json_Results/vodh_c_results_3072.json original_paper_results_backup.json
cp vodh_c_results.json Results/Json_Results/vodh_c_results_3072.json
python Source/vodh_plots_c.py
The output file from a fresh run may differ substantially from the archived Windows measurements.
Implementation parameters and tests
The current source uses a 3072-bit RSA modulus, a hardcoded 3072-bit Group 15 ElGamal modulus with generator 2, and 256-bit session-key material. The accepted paper reports a 1153-byte core encapsulation : RSA ciphertext (384 bytes) + ElGamal ciphertext (768 bytes) + order bit (1 byte). The C struct also contains AES-GCM payload fields; its raw in-memory size is not an on-wire serialization of the 1153-byte KEM encapsulation.

The current Source/main.c reports these checks: correctness (T1), VRF determinism (T2), proof acceptance (T3), wrong-public-key rejection (T4), tampering rejection (T5), wrong-key rejection (T6), hash-bridge sensitivity (T7) , different-input VRF output (T8), and public-key proof verification (T9). These implementation tests do not establish cryptographic security or replace the paper's security analysis.
Limitations and release status
- The software has not undergone an independent cryptographic security audit or RFC 9381 conformance testing.
- It is not post-quantum secure and is not intended for real-world secret protection or production TLS.
- The chosen-ciphertext DS-OW assumption is explicit in the paper; the paper does not reduce it to RSA-OAEP and DDH alone.
- The current source/test labels require reconciliation with the accepted paper. See docs/ARTIFACT_AUDIT.md before making a final publication release.
- No license is included in this review package because authorization for a particular software license has not been provided. Contact the copyright holders regarding reuse.
Quote
Missaoui Mohammed El Amine and Qian Weizhong, “VODH-KEM: Dual-Hardness Hybrid Key Encapsulation With VRF Ordering and Cross-Verification,” IEEE Access , accepted 2026. DOI pending.
