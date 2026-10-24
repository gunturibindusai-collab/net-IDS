# TestMyNIDS - Network Intrusion Detection Testing Framework

[![NIDS Engine](https://img.shields.io/badge/NIDS-Suricata%20%7C%20Snort-blue.svg)](https://suricata.io)
[![Ruleset](https://img.shields.io/badge/Rules-ET%20Open%20%7C%20GPL-orange.svg)](https://rules.emergingthreats.net)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2-green.svg)](https://ubuntu.com)
[![Tests](https://img.shields.io/badge/Tests-15%20Categories%20%2B%20CHAOS-purple.svg)](./tmNIDS)
[![License](https://img.shields.io/badge/Attribution-3CORESec-lightgrey.svg)](https://github.com/3CORESec/testmynids.org)

A robust, practical network intrusion detection testing framework replicating and modernizing **[3CORESec/testmynids.org](https://github.com/3CORESec/testmynids.org)**. This framework enables security engineers and SOC analysts to empirically generate, observe, and verify NIDS detection coverage against standard **Emerging Threats (ET Open)** and **Snort** rulesets in an isolated, controlled lab environment.

---

## 1. Project Background & Architecture

The original `testmynids.org` project centralized detection validation for network security sensors. However, because the public `testmynids.org` domain is no longer active on public DNS, this replication introduces a self-contained local architecture that eliminates brittle external dependencies while faithfully reproducing the original test suite.

```
+---------------------------------------------------------------------------------+
|                            Component A: Test Runner                             |
|                                    tmNIDS                                       |
|  - Interactive Menu (ANSI terminal UI)                                          |
|  - Script / CLI Execution (-1 to -15, -99 CHAOS, -t <target>, -l, -h)           |
|  - Dependency checks (curl, nc, dig, openssl) with helpful guidance            |
|  - Safe timeouts (--max-time, -w), colorized reporting, and log writer          |
+---------------------------------------+-----------------------------------------+
                                        |
                                        | (HTTP / TLS / DNS / TCP)
                                        v
+---------------------------------------------------------------------------------+
|                        Component B: Test Resource Server                        |
|                                 server/app.py                                   |
|  - Pure Python 3 standard library (zero external pip packages required)        |
|  - Endpoints: /uid/index.html (uid=0(root) response)                           |
|  - Harmless Payloads: PE/UPX executable, PDF with /EmbeddedFiles, C2 Beacon     |
|  - Dynamic Indicators: Basic Auth headers, malicious User-Agents, Adware URIs  |
+---------------------------------------+-----------------------------------------+
                                        |
                                        | (Packets observed on lo / eth0)
                                        v
+---------------------------------------------------------------------------------+
|                       Component C: NIDS Verification Suite                      |
|                  Suricata 8.x + nids/rules + verify_nids.py                     |
|  - nids/suricata.yaml (Configured for eve.json & fast.log outputs)              |
|  - nids/rules/tmnids.rules (Emerging Threats rules matching all 15 tests)       |
|  - nids/verify_nids.py (Empirical detection scorer: DETECTED vs MISSED)        |
|  - nids/run_lab_test.sh (Single-command end-to-end automated lab orchestrator)  |
+---------------------------------------------------------------------------------+
```

---

## 2. Test Catalog & Detection Signatures

| Test ID | Name | Protocol | Simulated Network Activity | Expected ET / Snort Rule | Expected SID |
|:---:|---|:---:|---|---|:---:|
| **1** | Linux UID | HTTP | `GET /uid/index.html` returning `uid=0(root)` | `GPL ATTACK_RESPONSE id check returned root` | `2100498` |
| **2** | HTTP Basic Authentication | HTTP | Cleartext header `Authorization: Basic cm9vdDpyb290` | `ET POLICY Cleartext Basic Auth with root credentials` | `2003195` |
| **3** | Malware User-Agents | HTTP | User-Agents: `BlackSun`, `HttpDownload`, `agent`, `MSIE`, `JEDI-VCL` | `ET MALWARE Suspicious User-Agent (*)` | `2008983`, `2003158`, `2003056`, `2006380` |
| **4** | Bad Certificates & CAs | TLS / HTTP | Probes `edellroot.badssl.com`, `superfish.badssl.com`, and OWASP ZAP test certificate | `ET POLICY Suspicious * CA Certificate Observed` | `2022134`, `2020493`, `2021941` |
| **5** | Tor Activity | DNS & TLS | DNS query for `.onion` host and TCP probes to active Tor directory relays | `ET TOR .onion DNS query lookup` | `2020001` |
| **6** | EXE / Packed Executable | HTTP | Downloads `/exe/calc.exe` (benign DOS/PE binary with `UPX0`/`UPX1` section headers) | `ET POLICY PE EXE or DLL Windows file download HTTP` / `UPX` | `2014520`, `2000419` |
| **7** | PDF with Embedded File | HTTP | Downloads `/pdf/pdf.pdf` (valid minimal PDF containing `/EmbeddedFiles` dictionary) | `ET POLICY PDF With Embedded File` | `2014162` |
| **8** | Outbound SSH Scan | SSH / TCP | SYN connection probe to TCP port 22 | `ET SCAN Potential Outbound SSH Scan` | `2001219` |
| **9** | Miscellaneous Domains | DNS | Queries `sinkhole.cert.pl` (CERT Polska Sinkhole), `.su` TLD, and dynamic DNS | `ET DNS Query to CERT Polska Sinkhole` / `ET INFO` | `2024897`, `2010002` |
| **10** | Anonymous Filesharing | TLS | Initiates TLS handshake with SNI `fromsmash.com:443` | `ET POLICY Anonymous File Sharing Domain Observed` | `2010010` |
| **11** | External IP Lookup | DNS / HTTP | Probes public IP lookup APIs (`api.ipify.org`, `ipinfo.io`, `icanhazip.com`) | `ET POLICY External IP Address Lookup (*)` | `2021997`, `2020716`, `2036304` |
| **12** | URL Shorteners | DNS / HTTP | Requests known URL shorteners (`zshorten.com`, `cutt.ly`, `lk.tc`) | `ET POLICY URL Shortener Domain Lookup` | `2038568`, `2038992` |
| **13** | Policy Violation - Gaming | HTTP | Sends `Nintendo Wii` User-Agent and requests `Second_Life_Setup.exe` installer | `ET POLICY Nintendo Wii User-Agent` / `Second Life` | `2014718`, `2013910` |
| **14** | Adware / PUP Indicators | HTTP | Queries adware URIs: `/php/rpc_uci.php`, `/keywords/kyf`, `/protector.exe` | `ET ADWARE_PUP Suspicious Adware Activity (*)` | `2003060`, `2002001`, `2002092` |
| **15** | Malware C2 Beacon | HTTP | Dispatches simulated Emotet base64 POST body and `sleep 20` User-Agent GET | `ET TROJAN Win32/Emotet/Geodo Beacon Outbound` | `2027793`, `2016568` |
| **99** | **CHAOS Mode** | ALL | Sequentially executes all 15 tests for full sensor validation | Full Suite Coverage | Multiple |

---

## 3. Safety & Lab Boundaries

To adhere to cybersecurity best practices and responsible disclosure:
- **No Live Malware**: No actual malicious binaries are hosted or executed. The test executables are harmless DOS/PE binary stubs containing non-executable UPX headers.
- **No Real C2 Infrastructure**: Tests do not contact real adversary infrastructure; simulated C2 beacons are directed to controlled lab endpoints.
- **Controlled Probes**: Port scans are strictly bounded to a single target port (port 22) with 2-3 second socket timeouts.
- **Safe Substitutions**: Where original third-party endpoints are retired, harmless local fixtures provide verifiable detection equivalents.

---

## 4. Environment & Quickstart

### Prerequisites (Windows + WSL2 or Linux)

On Ubuntu / Debian / WSL2, install the required network tools and Suricata:
```bash
sudo apt-get update
sudo apt-get install -y curl netcat-openbsd bind9-dnsutils openssl suricata python3
```

Make all scripts executable:
```bash
chmod +x tmNIDS server/start_server.sh nids/run_lab_test.sh tests/test_runner.sh helpers/analyze_tcpdump.sh
```

---

## 5. Usage Guide

### Mode 1: Interactive Menu
Run `tmNIDS` without arguments to launch the interactive numbered wizard:
```bash
./tmNIDS
```

You will see:
```text
 _             _   _ _____ _____   _____ 
| |           | \ | |_   _|  __ \ / ____|
| |_ _ __ ___ |  \| | | | | |  | | (___  
| __|  _   _ \| .   | | | | |  | |\___ \ 
| |_| | | | | | |\  |_| |_| |__| |____) |
 \__|_| |_| |_|_| \_|_____|_____/|_____/ 

tmNIDS - NIDS detection tester - @3CORESec (Replication v2.1.0-replica)
Project: https://github.com/3CORESec/testmynids.org
Target:  http://127.0.0.1:8080 | Log: tmnids_run.log

Choose which test you'd like to run: 

 1) Linux UID
 2) HTTP Basic Authentication
 3) HTTP Malware User-Agent
...
16) CHAOS! RUN ALL!
17) Quit!
```

### Mode 2: Command-Line / Script Mode
Run specific tests or all tests directly:
```bash
# View test catalog and help
./tmNIDS -h

# Run Test 1 (Linux UID) against a local test server
./tmNIDS -t 127.0.0.1:8080 -1

# Run Test 2 (HTTP Basic Authentication)
./tmNIDS -t 127.0.0.1:8080 -2

# Run Test 3 (Malware User-Agents)
./tmNIDS -t 127.0.0.1:8080 -3

# Run CHAOS Mode (Executes all 15 tests sequentially)
./tmNIDS -t 127.0.0.1:8080 -99
```

---

## 6. Running Component B: Test Resource Server

To host the harmless test indicators and payloads in your local network or lab:
```bash
# Start server on default port 8080
python3 server/app.py --port 8080

# Or run via helper script:
./server/start_server.sh 8080
```

To test the exact hostname `testmynids.org` locally, add this entry to `/etc/hosts`:
```text
127.0.0.1 testmynids.org
```

---

## 7. NIDS Integration & Automated Verification

### The Golden Rule: Traffic Generation != Detection Success
Generating network activity merely verifies that packets left the sender. Detection requires:
1. Traffic properly traverses the monitored network interface (e.g. `lo`, `eth0`, SPAN port).
2. Checksum offloading does not cause the IDS packet capture driver to drop packets (`checksum-validation: no` in `suricata.yaml`).
3. Application payload visibility: For encrypted TLS traffic, the NIDS can inspect Server Name Indication (SNI) and certificate subjects during the handshake, but application payloads remain opaque unless TLS termination / proxying is deployed.

### Multi-Interface Lab Architecture
In WSL2 / Linux environments, network traffic traverses two distinct interfaces:
1. **Loopback (`lo`)**: Handles all traffic directed to the local test resource server (`127.0.0.1:8080`), including UID output, Basic Auth headers, malware User-Agents, PE/UPX downloads, PDF downloads, and C2 beacons.
2. **Egress Interface (`eth0`)**: Handles external DNS lookups (e.g. `dig @8.8.8.8`) and external TLS handshakes (e.g. `badssl.com`, `fromsmash.com`, `api.ipify.org`).

The lab test script (`nids/run_lab_test.sh`) automatically provisions Suricata in **`autofp` multi-interface mode** monitoring both `lo` and `eth0` concurrently, ensuring complete visibility across all local and egress traffic.

### Test Environment Categorization & Limitations

| Test Category | Target / Scope | Offline / Air-Gapped Capable? | Notes & Detection Mechanism |
|---|---|:---:|---|
| **Test 1: Linux UID** | Local (`/uid/index.html`) | **Yes** | Server responds with `uid=0(root)`; triggers SID 2100498. |
| **Test 2: Basic Auth** | Local (`/`) | **Yes** | Request header `Authorization: Basic cm9vdDpyb290`; triggers SID 2003195. |
| **Test 3: User-Agents** | Local (`/`) | **Yes** | Dispatches BlackSun, HttpDownload, agent, MSIE, JEDI-VCL; triggers 5 SIDs. |
| **Test 4: Bad CAs & Certs** | Hybrid (`badssl.com` + Local) | **Yes** (Local cert) | Probes badssl endpoints and downloads local OWASP ZAP test certificate (SID 2021941). |
| **Test 5: Tor Activity** | External (DNS + Relay list) | No (Requires Internet) | Queries `3wzn5p2yiumh7akj.onion` via DNS; triggers SID 2020001. |
| **Test 6: EXE / UPX** | Local (`/exe/calc.exe`) | **Yes** | Downloads harmless PE stub with `UPX0`/`UPX1` headers; triggers SIDs 2014520, 2000419. |
| **Test 7: PDF Embedded File**| Local (`/pdf/pdf.pdf`) | **Yes** | Downloads valid PDF with `/EmbeddedFiles` structure; triggers SID 2014162. |
| **Test 8: SSH Outbound Scan**| Local (`127.0.0.1:22`) | **Yes** | Probes TCP port 22 with SYN flag; triggers SID 2001219. |
| **Test 9: Misc DNS** | External (DNS sinkholes) | No (Requires Internet) | Queries `sinkhole.cert.pl` (SID 2024897), `.su` TLD (SID 2010002), `no-ip.com`. |
| **Test 10: Anonymous Sharing**| External (`fromsmash.com:443`) | No (Requires Internet) | TLS ClientHello with SNI `fromsmash.com`; triggers SID 2010010. |
| **Test 11: External IP Lookup**| External (`ipify.org`, etc.) | No (Requires Internet) | DNS and HTTP GET to `api.ipify.org`; triggers SIDs 2021997, 2047702. |
| **Test 12: URL Shortener** | External (`cutt.ly`, etc.) | No (Requires Internet) | DNS and HTTP GET to `cutt.ly`, `zshorten.com`; triggers SIDs 2038568, 2038569. |
| **Test 13: Gaming Policy** | Local (`/Second_Life_Setup.exe`) | **Yes** | Wii User-Agent and Second Life installer download; triggers SIDs 2014718, 2013910. |
| **Test 14: Adware / PUP** | Local (`/php/rpc_uci.php`, etc.)| **Yes** | Queries known adware URI paths; triggers SIDs 2003060, 2002001, 2002092. |
| **Test 15: Malware C2 Beacon**| Local (`/`) | **Yes** | Simulated Emotet POST body and `sleep 20` User-Agent; triggers SIDs 2027793, 2016568. |

### Single-Command Lab Execution & Verification
To start the test server, launch Suricata, execute all tests, and verify detections automatically:
```bash
# Run with root privileges (required for raw packet capture)
sudo ./nids/run_lab_test.sh -99
```

Or test a single specific test case:
```bash
sudo ./nids/run_lab_test.sh -1
```

### Actual Lab Verification Results (Suricata 8.0.3)
```text
================================================================================
       TestMyNIDS Detection Verification Report (Suricata NIDS)
================================================================================
Log Source Evaluated: /mnt/c/Users/LENOVO/OneDrive/Desktop/net-ids/nids/logs/eve.json
Overall Detection Score: 15/15 tests (100.0%)

ID   | Test Name                        | Protocol   | Status         | Alerts
--------------------------------------------------------------------------------
#1   | Linux UID                        | HTTP       | [+] DETECTED   | 1     
#2   | HTTP Basic Authentication        | HTTP       | [+] DETECTED   | 1     
#3   | HTTP Malware User-Agent          | HTTP       | [+] DETECTED   | 5     
#4   | Bad Certificates & CAs           | TLS / HTTP | [+] DETECTED   | 3     
#5   | Tor .onion & Relay Nodes         | DNS & TLS  | [+] DETECTED   | 1     
#6   | EXE or DLL Download & Packed PE  | HTTP       | [+] DETECTED   | 6     
#7   | PDF Download with Embedded File  | HTTP       | [+] DETECTED   | 1     
#8   | Simulate SSH Outbound Scan       | SSH / TCP  | [+] DETECTED   | 1     
#9   | Miscellaneous Domains            | DNS        | [+] DETECTED   | 3     
#10  | Anonymous Filesharing Website    | TLS        | [+] DETECTED   | 1     
#11  | External IP Address Lookup       | DNS / HTTP | [+] DETECTED   | 5     
#12  | URL Shortener Domains            | DNS / HTTP | [+] DETECTED   | 4     
#13  | Policy Violation - Gaming        | HTTP       | [+] DETECTED   | 2     
#14  | Adware PUP Indicators            | HTTP       | [+] DETECTED   | 3     
#15  | Malware C2 Beacon                | HTTP       | [+] DETECTED   | 2     
--------------------------------------------------------------------------------

--- Signature & Detection Details ---

[+] Test 1: Linux UID (SID: 2100498) -> GPL ATTACK_RESPONSE id check returned root
[+] Test 2: HTTP Basic Authentication (SID: 2003195) -> ET POLICY Cleartext Basic Auth with root credentials
[+] Test 3: HTTP Malware User-Agent -> 5 alerts: BlackSun, HttpDownload, agent, MSIE, JEDI-VCL
[+] Test 4: Bad Certificates & CAs -> eDellRoot (2022134), Superfish (2020493), OWASP ZAP (2021941)
[+] Test 5: Tor .onion & Relay Nodes (SID: 2020001) -> ET TOR .onion DNS query lookup
[+] Test 6: EXE Download & Packed PE -> PE EXE download (2014520) & UPX Packed PE (2000419)
[+] Test 7: PDF Download with Embedded File (SID: 2014162) -> ET POLICY PDF With Embedded File
[+] Test 8: Simulate SSH Outbound Scan (SID: 2001219) -> ET SCAN Potential Outbound SSH Scan
[+] Test 9: Miscellaneous Domains -> CERT Polska Sinkhole (2024897), .su TLD, no-ip.com
[+] Test 10: Anonymous Filesharing Website (SID: 2010010) -> fromsmash.com TLS SNI
[+] Test 11: External IP Address Lookup -> ipify.org DNS (2021997) & HTTP (2047702), ipinfo.io, icanhazip
[+] Test 12: URL Shortener Domains -> cutt.ly DNS (2038568), cutt.ly HTTP (2038569), zshorten.com HTTP
[+] Test 13: Policy Violation - Gaming -> Nintendo Wii UA (2014718) & Second Life download (2013910)
[+] Test 14: Adware PUP Indicators -> rpc_uci.php (2003060), keywords/kyf (2002001), protector.exe (2002092)
[+] Test 15: Malware C2 Beacon -> Emotet/Geodo Beacon (2027793) & sleep 20 UA (2016568)
================================================================================
```

---

## 8. Automated Regression Tests

Run the built-in automated test suite to verify script permissions, CLI argument parsing, server endpoints, and verifier logic:
```bash
./tests/test_runner.sh
```

---

## 9. Helper Scripts & Packet Analysis

To analyze `tcpdump` or PCAP capture outputs:
```bash
tcpdump -nn -r capture.pcap > dump.txt
./helpers/analyze_tcpdump.sh dump.txt
```

---

## 10. Attribution & Acknowledgments

This project is a replication and lab enhancement of **[TestMyNIDS](https://github.com/3CORESec/testmynids.org)** created by **[@3CORESec](https://twitter.com/3CORESec)**.
Full credit is extended to the original authors for establishing the test methodology, ruleset mappings, and original `tmNIDS` tool.
