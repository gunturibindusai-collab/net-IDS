#!/usr/bin/env bash
# ==============================================================================
# TestMyNIDS Automated Test Suite
# Validates runner flags, CLI parsing, dependency checks, server responses,
# and verification engine outputs.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TMNIDS="$PROJECT_ROOT/tmNIDS"
SERVER="$PROJECT_ROOT/server/app.py"
VERIFIER="$PROJECT_ROOT/nids/verify_nids.py"

TOTAL_TESTS=0
PASSED_TESTS=0

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[32m"
COLOR_RED="\033[31m"
COLOR_CYAN="\033[36m"
COLOR_BOLD="\033[1m"

assert_equal() {
  local test_name="$1"
  local actual="$2"
  local expected="$3"
  ((TOTAL_TESTS++))

  if [ "$actual" == "$expected" ]; then
    echo -e "  ${COLOR_GREEN}[PASS]${COLOR_RESET} $test_name"
    ((PASSED_TESTS++))
  else
    echo -e "  ${COLOR_RED}[FAIL]${COLOR_RESET} $test_name (Expected: '$expected', Got: '$actual')"
  fi
}

assert_contains() {
  local test_name="$1"
  local output="$2"
  local needle="$3"
  ((TOTAL_TESTS++))

  if echo "$output" | grep -q "$needle"; then
    echo -e "  ${COLOR_GREEN}[PASS]${COLOR_RESET} $test_name"
    ((PASSED_TESTS++))
  else
    echo -e "  ${COLOR_RED}[FAIL]${COLOR_RESET} $test_name (Did not find: '$needle')"
  fi
}

echo -e "\n${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}            TestMyNIDS Automated Regression Test Suite            ${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}\n"

# Test 1: Executable check
echo -e "${COLOR_BOLD}[1] Verifying tmNIDS script existence and permissions${COLOR_RESET}"
assert_equal "tmNIDS exists" "$([ -f "$TMNIDS" ] && echo "yes")" "yes"
assert_equal "tmNIDS is executable" "$([ -x "$TMNIDS" ] && echo "yes")" "yes"

# Test 2: Help flag
echo -e "\n${COLOR_BOLD}[2] Verifying help options (--help and -h)${COLOR_RESET}"
help_out="$("$TMNIDS" --help 2>&1 || true)"
assert_contains "--help displays banner" "$help_out" "tmNIDS - NIDS detection tester"
assert_contains "--help displays test list" "$help_out" "Linux UID"
assert_contains "--help displays CHAOS option" "$help_out" "CHAOS! Run all!"

# Test 3: List flag
echo -e "\n${COLOR_BOLD}[3] Verifying list option (-l)${COLOR_RESET}"
list_out="$("$TMNIDS" -l 2>&1 || true)"
assert_contains "-l displays available tests" "$list_out" "These are the available tests"

# Test 4: Dependency check flag
echo -e "\n${COLOR_BOLD}[4] Verifying dependency verification routine (--check-deps)${COLOR_RESET}"
dep_out="$("$TMNIDS" --check-deps 2>&1 || true)"
assert_contains "--check-deps runs" "$dep_out" "Checking required tools"

# Test 5: Unknown flag error handling
echo -e "\n${COLOR_BOLD}[5] Verifying invalid argument handling${COLOR_RESET}"
err_out="$("$TMNIDS" --invalid-flag-1234 2>&1 || true)"
assert_contains "Unknown option triggers error" "$err_out" "Unknown option: --invalid-flag-1234"

# Test 6: Custom logging verification
echo -e "\n${COLOR_BOLD}[6] Verifying custom log generation${COLOR_RESET}"
test_log="/tmp/test_custom_$$.log"
rm -f "$test_log"
TMNIDS_LOG_FILE="$test_log" "$TMNIDS" -t 127.0.0.1:9999 -1 > /dev/null 2>&1 || true
assert_equal "Custom log file created" "$([ -s "$test_log" ] && echo "yes")" "yes"
assert_contains "Log contains test execution record" "$(cat "$test_log")" "Executing Test 1: Linux UID"
rm -f "$test_log"

# Test 7: Local Server & HTTP Indicators
echo -e "\n${COLOR_BOLD}[7] Verifying local test resource server endpoints${COLOR_RESET}"
test_port=8991
python3 "$SERVER" --port "$test_port" > /dev/null 2>&1 &
srv_pid=$!
sleep 1

# Test endpoint /uid/index.html
uid_resp="$(curl -s "http://127.0.0.1:$test_port/uid/index.html")"
assert_equal "/uid/index.html returns uid=0(root)" "$uid_resp" "uid=0(root) gid=0(root) groups=0(root)"

# Test calc.exe download
calc_len="$(curl -s "http://127.0.0.1:$test_port/exe/calc.exe" | wc -c)"
assert_equal "/exe/calc.exe returns valid binary size (>500 bytes)" "$(( calc_len > 500 ? 1 : 0 ))" "1"

# Test C2 beacon POST
post_resp="$(curl -s -X POST "http://127.0.0.1:$test_port/" -d '=eyJHVUlEIjoi=IlR5cGUiOJUeXBlIj')"
assert_contains "POST beacon returns 200 OK indicator" "$post_resp" "OK - TestMyNIDS Beacon Received"

kill "$srv_pid" 2>/dev/null || true
wait "$srv_pid" 2>/dev/null || true

# Test 8: NIDS Verification Engine Test
echo -e "\n${COLOR_BOLD}[8] Verifying nids/verify_nids.py parser logic${COLOR_RESET}"
mock_eve="/tmp/mock_eve_$$.json"
cat << 'EOF' > "$mock_eve"
{"event_type": "alert", "alert": {"signature_id": 2100498, "signature": "GPL ATTACK_RESPONSE id check returned root", "category": "bad-unknown"}}
{"event_type": "alert", "alert": {"signature_id": 2003195, "signature": "ET POLICY Cleartext Basic Auth with root credentials", "category": "policy-violation"}}
EOF

ver_out="$(python3 "$VERIFIER" --eve "$mock_eve" -t 1 2)"
assert_contains "Verifier displays Test 1" "$ver_out" "Linux UID"
assert_contains "Verifier displays Test 2" "$ver_out" "HTTP Basic Authentication"
assert_contains "Verifier reports DETECTED" "$ver_out" "DETECTED"
assert_contains "Verifier reports 2/2 score" "$ver_out" "2/2 tests (100.0%)"
rm -f "$mock_eve"

# Final Results
echo -e "\n${COLOR_CYAN}-----------------------------------------------------------------${COLOR_RESET}"
echo -e "${COLOR_BOLD}Total Assertions: $TOTAL_TESTS | Passed: $PASSED_TESTS | Failed: $((TOTAL_TESTS - PASSED_TESTS))${COLOR_RESET}"
if [ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ]; then
  echo -e "${COLOR_GREEN}${COLOR_BOLD}ALL AUTOMATED TESTS PASSED!${COLOR_RESET}\n"
  exit 0
else
  echo -e "${COLOR_RED}${COLOR_BOLD}SOME TESTS FAILED!${COLOR_RESET}\n"
  exit 1
fi
