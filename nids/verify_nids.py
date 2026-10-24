#!/usr/bin/env python3
"""
TestMyNIDS - NIDS Alert Verification Utility
Parses Suricata eve.json / fast.log and verifies whether the generated test traffic
triggered the expected Emerging Threats (ET) / Snort detection signatures.

Critical Cybersecurity Principle:
Traffic Generation Success != Detection Success.
This utility provides empirical proof of whether the NIDS sensor actually detected the activity.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

# Mapping of TestMyNIDS Test IDs to expected SIDs and signatures
TEST_SIGNATURE_MAP = {
    1: {
        "name": "Linux UID",
        "protocol": "HTTP",
        "expected_sids": [2100498],
        "category": "ATTACK_RESPONSE",
        "notes": "Triggers on uid=0(root) returned in HTTP response",
    },
    2: {
        "name": "HTTP Basic Authentication",
        "protocol": "HTTP",
        "expected_sids": [2003195],
        "category": "POLICY",
        "notes": "Triggers on cleartext Basic Auth with root credentials",
    },
    3: {
        "name": "HTTP Malware User-Agent",
        "protocol": "HTTP",
        "expected_sids": [2008983, 2003158, 2003056, 2001001, 2006380],
        "category": "MALWARE",
        "notes": "Triggers on BlackSun, HttpDownload, agent, MSIE, JEDI-VCL",
    },
    4: {
        "name": "Bad Certificates & CAs",
        "protocol": "TLS / HTTP",
        "expected_sids": [2022134, 2020493, 2021941, 2029345, 2033098, 2045597, 2053979, 2054198],
        "category": "POLICY / CERT",
        "notes": "Triggers on badssl SNIs and OWASP ZAP test cert (2021941)",
    },
    5: {
        "name": "Tor .onion & Relay Nodes",
        "protocol": "DNS & TLS",
        "expected_sids": [2020001],
        "category": "TOR",
        "notes": "Triggers on .onion DNS query",
    },
    6: {
        "name": "EXE or DLL Download & Packed PE",
        "protocol": "HTTP",
        "expected_sids": [2014520, 2000419],
        "category": "POLICY",
        "notes": "Triggers on .exe URI and UPX section in payload",
    },
    7: {
        "name": "PDF Download with Embedded File",
        "protocol": "HTTP",
        "expected_sids": [2014162, 2024213],
        "category": "POLICY",
        "notes": "Triggers on /EmbeddedFiles dictionary inside PDF stream",
    },
    8: {
        "name": "Simulate SSH Outbound Scan",
        "protocol": "SSH / TCP",
        "expected_sids": [2001219],
        "category": "SCAN",
        "notes": "Triggers on TCP SYN probe to port 22",
    },
    9: {
        "name": "Miscellaneous Domains",
        "protocol": "DNS",
        "expected_sids": [2024897, 2010002, 2010003],
        "category": "DNS / INFO",
        "notes": "Triggers on sinkhole.cert.pl, .su TLD, and dynamic DNS",
    },
    10: {
        "name": "Anonymous Filesharing Website",
        "protocol": "TLS",
        "expected_sids": [2010010],
        "category": "POLICY",
        "notes": "Triggers on TLS SNI to fromsmash.com",
    },
    11: {
        "name": "External IP Address Lookup",
        "protocol": "DNS / HTTP",
        "expected_sids": [2021997, 2047702, 2025331, 2017398, 2020716, 2036304, 2844906, 2052027, 2022082],
        "category": "POLICY",
        "notes": "Triggers on lookups to ipify, ipinfo, icanhazip",
    },
    12: {
        "name": "URL Shortener Domains",
        "protocol": "DNS / HTTP",
        "expected_sids": [2038568, 2038569, 2038992, 2035742],
        "category": "POLICY",
        "notes": "Triggers on zshorten, cutt.ly, lk.tc lookups",
    },
    13: {
        "name": "Policy Violation - Gaming",
        "protocol": "HTTP",
        "expected_sids": [2014718, 2013910],
        "category": "POLICY",
        "notes": "Triggers on Wii User-Agent and Second_Life_Setup.exe download",
    },
    14: {
        "name": "Adware PUP Indicators",
        "protocol": "HTTP",
        "expected_sids": [2003060, 2002001, 2002092],
        "category": "ADWARE_PUP",
        "notes": "Triggers on rpc_uci.php, keywords/kyf, and protector.exe",
    },
    15: {
        "name": "Malware C2 Beacon",
        "protocol": "HTTP",
        "expected_sids": [2027793, 2016568],
        "category": "TROJAN",
        "notes": "Triggers on Emotet POST payload and 'sleep 20' User-Agent",
    },
}


def parse_eve_json(log_path):
    """Parse Suricata eve.json for alert events."""
    alerts = defaultdict(list)
    if not os.path.isfile(log_path):
        return alerts

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if record.get("event_type") == "alert":
                    alert_data = record.get("alert", {})
                    sid = alert_data.get("signature_id")
                    if sid:
                        alerts[sid].append(
                            {
                                "signature": alert_data.get("signature", "Unknown"),
                                "category": alert_data.get("category", ""),
                                "severity": alert_data.get("severity", 3),
                                "src_ip": record.get("src_ip", ""),
                                "src_port": record.get("src_port", ""),
                                "dest_ip": record.get("dest_ip", ""),
                                "dest_port": record.get("dest_port", ""),
                                "timestamp": record.get("timestamp", ""),
                            }
                        )
            except json.JSONDecodeError:
                continue

    return alerts


def parse_fast_log(log_path):
    """Fallback parser for Suricata fast.log format."""
    alerts = defaultdict(list)
    if not os.path.isfile(log_path):
        return alerts

    import re
    # Format: 10/24/2026-16:30:00.123456  [**] [1:2100498:7] GPL ATTACK_RESPONSE ... [**] [Classification: ...] ...
    pattern = re.compile(r"\[\d+:(\d+):\d+\]\s+([^\[\*]+)")

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                sid = int(m.group(1))
                sig_name = m.group(2).strip()
                alerts[sid].append({"signature": sig_name, "raw": line.strip()})

    return alerts


def evaluate_detection(alerts, specific_tests=None):
    """Compare observed alerts against expected test signatures."""
    results = []
    tests_to_eval = specific_tests if specific_tests else sorted(TEST_SIGNATURE_MAP.keys())

    detected_count = 0
    total_evaluated = len(tests_to_eval)

    for test_id in tests_to_eval:
        info = TEST_SIGNATURE_MAP.get(test_id)
        if not info:
            continue

        expected_sids = info["expected_sids"]
        matching_alerts = []
        for sid in expected_sids:
            if sid in alerts:
                matching_alerts.extend(alerts[sid])

        status = "DETECTED" if len(matching_alerts) > 0 else "NOT DETECTED"
        if status == "DETECTED":
            detected_count += 1

        results.append(
            {
                "test_id": test_id,
                "name": info["name"],
                "protocol": info["protocol"],
                "expected_sids": expected_sids,
                "status": status,
                "alert_count": len(matching_alerts),
                "matched_alerts": matching_alerts,
                "notes": info["notes"],
            }
        )

    return results, detected_count, total_evaluated


def print_report(results, detected_count, total_evaluated, log_source):
    """Render a clean, professional security report table to stdout."""
    col_reset = "\033[0m"
    col_bold = "\033[1m"
    col_green = "\033[32m"
    col_red = "\033[31m"
    col_yellow = "\033[33m"
    col_cyan = "\033[36m"

    print("\n" + "=" * 80)
    print(f"{col_bold}       TestMyNIDS Detection Verification Report (Suricata NIDS){col_reset}")
    print("=" * 80)
    print(f"Log Source Evaluated: {log_source}")
    detection_pct = (detected_count / total_evaluated * 100) if total_evaluated > 0 else 0
    print(
        f"Overall Detection Score: {col_bold}{detected_count}/{total_evaluated} tests ({detection_pct:.1f}%){col_reset}\n"
    )

    header = f"{'ID':<4} | {'Test Name':<32} | {'Protocol':<10} | {'Status':<14} | {'Alerts':<6}"
    print(col_cyan + header + col_reset)
    print("-" * 80)

    for r in results:
        t_id = f"#{r['test_id']}"
        name = r["name"][:32]
        proto = r["protocol"][:10]
        status_str = (
            f"{col_green}[+] DETECTED{col_reset}"
            if r["status"] == "DETECTED"
            else f"{col_red}[-] MISSED  {col_reset}"
        )
        count = r["alert_count"]
        print(f"{t_id:<4} | {name:<32} | {proto:<10} | {status_str} | {count:<6}")

    print("-" * 80)

    # Detailed alerts breakdown
    print(f"\n{col_bold}--- Signature & Detection Details ---{col_reset}")
    for r in results:
        if r["status"] == "DETECTED":
            print(f"\n{col_green}[+] Test {r['test_id']}: {r['name']}{col_reset}")
            print(f"    Expected SIDs: {r['expected_sids']}")
            print(f"    Triggered Alerts ({r['alert_count']}):")
            seen_sigs = set()
            for a in r["matched_alerts"]:
                sig = a.get("signature", "Unknown")
                if sig not in seen_sigs:
                    seen_sigs.add(sig)
                    print(f"      * {sig}")
        else:
            print(f"\n{col_yellow}[-] Test {r['test_id']}: {r['name']} - NOT DETECTED{col_reset}")
            print(f"    Expected SIDs: {r['expected_sids']}")
            print(f"    Possible Reasons:")
            print(f"      1. Traffic was generated on unmonitored interface (check 'suricata -i <interface>')")
            print(f"      2. Traffic was TLS-encrypted and payload is opaque to NIDS (inspecting SNI/certs only)")
            print(f"      3. Checksum offloading dropped packets (set 'checksum-validation: no' in suricata.yaml)")
            print(f"      4. Local test server was not running during test execution")

    print("\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(description="TestMyNIDS Alert Verification Utility")
    parser.add_argument(
        "--eve",
        "-e",
        default="nids/logs/eve.json",
        help="Path to Suricata eve.json file (default: nids/logs/eve.json)",
    )
    parser.add_argument(
        "--fast",
        "-f",
        default="nids/logs/fast.log",
        help="Path to Suricata fast.log file (fallback)",
    )
    parser.add_argument(
        "--tests",
        "-t",
        nargs="+",
        type=int,
        help="Specific test IDs to verify (e.g., -t 1 2 3)",
    )
    parser.add_argument("--json-out", "-j", help="Path to write JSON verification report")
    args = parser.parse_args()

    log_source = ""
    alerts = defaultdict(list)

    if os.path.isfile(args.eve):
        log_source = args.eve
        alerts = parse_eve_json(args.eve)
    elif os.path.isfile(args.fast):
        log_source = args.fast
        alerts = parse_fast_log(args.fast)
    else:
        # Check fallback paths in /tmp/tmnids_logs/ or ./logs/
        fallbacks = [
            "/tmp/tmnids_logs/eve.json",
            "./logs/eve.json",
            "/var/log/suricata/eve.json",
            "/tmp/tmnids_logs/fast.log",
            "./logs/fast.log",
        ]
        for fb in fallbacks:
            if os.path.isfile(fb):
                log_source = fb
                alerts = parse_eve_json(fb) if "eve.json" in fb else parse_fast_log(fb)
                break

    if not log_source:
        print(f"[-] Error: Could not locate Suricata alert logs at '{args.eve}' or '{args.fast}'.")
        print("    Ensure Suricata has run and generated eve.json or fast.log.")
        sys.exit(1)

    results, detected, total = evaluate_detection(alerts, args.tests)
    print_report(results, detected, total, log_source)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "log_source": log_source,
                    "total_evaluated": total,
                    "detected_count": detected,
                    "detection_rate": detected / total if total > 0 else 0,
                    "results": results,
                },
                f,
                indent=2,
            )
        print(f"[+] Saved structured verification report to: {args.json_out}")


if __name__ == "__main__":
    main()
