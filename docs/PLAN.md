# TestMyNIDS Replication & Lab Framework: Implementation Plan

## 1. Project Background & Original Architecture

**Reference Repository:** `https://github.com/3CORESec/testmynids.org`
**Original Purpose:** Test and validate Network Intrusion Detection System (NIDS) detection coverage against standard Emerging Threats (ET Open) rulesets.

The original project consisted of:
- **`tmNIDS`**: A Bash script providing both an interactive numbered menu and command-line execution (`-1` through `-15`, `-99`) to simulate 15 distinct network attack patterns and policy violations.
- **`testmynids.org`**: A remote web server hosting specific test indicators (such as command execution output, test binaries, and specific URI paths).
- **`helpers/` & `pcaps/`**: Reference packet captures and traffic analysis utilities.

### Critical Discovery & Enhancement
The original public domain `testmynids.org` is currently decommissioned / does not resolve on public DNS (`curl: (6) Could not resolve host: testmynids.org`). To make this a functional, robust, and self-contained cybersecurity testing framework without brittle external dependencies:
1. We replicate the **Test Website & Resource Server** (`server/app.py` and `resources/`) to host all required payloads locally in a controlled lab environment.
2. We make the target host configurable via environment variable (`TMNIDS_TARGET_HOST`) or CLI argument (`--target`), while preserving default compatibility with `testmynids.org` (e.g. via `/etc/hosts` or local DNS).
3. We provide a **NIDS Integration & Verification Suite** with local Suricata configuration, detection rules, and an automated log parser (`verify_nids.py`).

---

## 2. Architecture & Components

```
+--------------------------------------------------------------+
|                    Component A: Test Runner                  |
|                    tmNIDS (Bash / WSL2)                      |
|  - Interactive Menu (select loop)                            |
|  - Script/CLI Mode (-1 to -15, -99 CHAOS, -l, -h)            |
|  - Dependency checks (curl, nc, dig, openssl)                |
|  - Colorized UI, timestamps, logging & safe timeouts         |
+------------------------------+-------------------------------+
                               |
                               | (HTTP / TLS / DNS / TCP)
                               v
+--------------------------------------------------------------+
|             Component B: Test Resource Server                |
|             server/app.py & resources/ (Python 3)            |
|  - /uid/index.html (Linux id command output: uid=0(root))     |
|  - /content_for_tests/2021941.txt (OWASP ZAP certificate)    |
|  - /exe/calc.exe (Harmless UPX-packed PE test file)          |
|  - /pdf/pdf.pdf (Benign PDF with /EmbeddedFiles indicator)   |
|  - /Second_Life_Setup.exe, /php/rpc_uci.php, /protector.exe  |
|  - Basic auth endpoint, C2 beacon POST listener              |
+------------------------------+-------------------------------+
                               |
                               | (Traffic observed on lo / veth)
                               v
+--------------------------------------------------------------+
|              Component C: NIDS Verification Suite            |
|              Suricata 8.x + nids/verify_nids.py              |
|  - nids/rules/tmnids.rules (ET Open signatures for all tests)|
|  - Automated eve.json / fast.log alert matching              |
|  - Distinction between traffic generation & rule detection   |
+--------------------------------------------------------------+
```

---

## 3. Test Categories & ET Open Signatures

| ID | Test Category | Protocols | Target / Indicators | Expected ET / Snort Rule SIDs |
|---|---|---|---|---|
| 1 | Linux UID | HTTP | `GET /uid/index.html` -> `uid=0(root)` | 2100498 (GPL ATTACK_RESPONSE id check returned root) |
| 2 | HTTP Basic Authentication | HTTP | `Authorization: Basic cm9vdDpyb290` | 2003195 (ET POLICY Cleartext Basic Auth) |
| 3 | Malware User-Agents | HTTP | User-Agents: `BlackSun`, `HttpDownload`, `agent`, `MSIE`, `JEDI-VCL` | 2008983, 2003158, 2003056, 2006380 |
| 4 | Bad CAs & Certificates | TLS, DNS | `edellroot.badssl.com`, `superfish.badssl.com`, OWASP ZAP Root CA | 2022134, 2020493, 2021941 |
| 5 | Tor Activity | DNS, TLS | DNS query for `.onion` host, connection to Tor node IP | ET Tor DNS / Known Tor Relay rules |
| 6 | EXE / Packed Download | HTTP | `GET /exe/calc.exe` (benign test PE with UPX marker) | 2014520, 2000419 (PE / UPX download) |
| 7 | PDF with Embedded File | HTTP | `GET /pdf/pdf.pdf` (benign PDF with `/EmbeddedFiles`) | 2014162, 2024213 (PDF embedded file) |
| 8 | Outbound SSH Scan | SSH/TCP | `nc -w3 <target> 22` | ET SCAN Potential SSH Scan / connection |
| 9 | Miscellaneous DNS | DNS | `sinkhole.cert.pl`, `nic.su`, `invalid.no-ip.com` | 2024897, ET INFO Soviet Union TLD, Dynamic DNS |
| 10 | Anonymous File Sharing | TLS/SNI | TLS ClientHello to `fromsmash.com:443` | ET POLICY File Sharing Service |
| 11 | External IP Lookup | HTTP/TLS | `api.ipify.org`, `ipinfo.io`, `icanhazip.com`, etc. | 2021997, 2020716, 2036304 (IP Lookup) |
| 12 | URL Shortener | HTTP/DNS | `zshorten.com`, `cutt.ly`, `lk.tc` | 2038992, 2038568 (URL Shorteners) |
| 13 | Policy Violation - Gaming | HTTP | `User-Agent: Nintendo Wii`, `Second_Life_Setup.exe` | 2014718, 2013910 |
| 14 | Adware / PUP Indicators | HTTP | `/php/rpc_uci.php`, `/keywords/kyf`, `/protector.exe` | 2003060, 2002001, 2002092 |
| 15 | Malware C2 Beacon | HTTP | POST base64 GUID payload, GET with `sleep 20` User-Agent | 2027793 (Emotet/Geodo), 2016568 |
| 99 | CHAOS / All Tests | ALL | Sequentially executes all 15 tests | Complete suite validation |

---

## 4. Staged Implementation Roadmap

- **Stage 1 — Repository Inspection & Project Foundation**
  - Verify Git repository, branch, and remote configuration.
  - Establish `.gitignore` to prevent tracking temporary artifacts and logs.
  - Document architecture, plan, and ET Open signature mappings in `docs/PLAN.md`.
  - Push Stage 1 milestone commit.

- **Stage 2 — Minimal Runnable Test Runner**
  - Implement `tmNIDS` Bash runner with:
    - Interactive menu mode (numbered select).
    - CLI / script mode (`-1` through `-15`, `-99`, `--list`, `--help`).
    - Dependency check routine (`curl`, `nc`, `dig`, `openssl`).
    - Colorized console status reporting, execution timer, and log writer.
    - Configurable target host (`TMNIDS_TARGET_HOST` defaulting to `testmynids.org` or local override).
  - Implement first set of safe HTTP tests (UID, Basic Auth, User-Agents).
  - Verify both interactive and CLI modes under WSL2.
  - Push Stage 2 milestone commit.

- **Stage 3 — Test Website and Resource Server**
  - Create `server/app.py`: Lightweight Python 3 HTTP server supporting all test endpoints.
  - Generate benign, safe indicator files:
    - `resources/uid/index.html` (returns `uid=0(root) gid=0(root) groups=0(root)`).
    - `resources/content_for_tests/2021941.txt` (OWASP ZAP certificate test file).
    - `resources/exe/calc.exe` (benign, minimal valid PE header with UPX signature).
    - `resources/pdf/pdf.pdf` (valid minimal PDF with benign embedded file object).
    - `resources/Second_Life_Setup.exe`, `resources/protector.exe`.
  - Verify test runner interaction with the local resource server.
  - Push Stage 3 milestone commit.

- **Stage 4 — Expand Test Suite to All 15 Categories**
  - Implement remaining categories: Tor, Bad CAs, Misc DNS, File Sharing, External IP, URL Shorteners, Gaming, Adware, and C2 Beacon.
  - Add timeout safety (`--max-time` on curl, `-w` on nc), defensive failure handling, and opt-in guards for external internet traffic.
  - Test all individual tests and Option 99 (CHAOS mode).
  - Push Stage 4 milestone commit.

- **Stage 5 — NIDS Integration & Verification Utility**
  - Provide Suricata configuration and custom test ruleset (`nids/rules/tmnids.rules`) corresponding to all 15 test categories.
  - Implement `nids/verify_nids.py`: Log parser that compares generated test traffic with Suricata `eve.json` alerts.
  - Provide a single-command lab test script (`nids/run_lab_test.sh`).
  - Document network interface capture and TLS limitations.
  - Push Stage 5 milestone commit.

- **Stage 6 — Reliability, Testing & Documentation**
  - Create automated test suite (`tests/test_runner.sh`) validating runner flags, help, and execution.
  - Write comprehensive `README.md` covering architecture, WSL2 setup, lab testing, troubleshooting, and MIT attribution.
  - Clean up temporary files and run full end-to-end verification.
  - Push final project commit.
