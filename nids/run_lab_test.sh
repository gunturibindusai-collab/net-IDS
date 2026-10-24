#!/usr/bin/env bash
# ==============================================================================
# TestMyNIDS - End-to-End Automated Lab Test & NIDS Verification Script
# Launches Suricata NIDS, starts local resource server, runs tmNIDS tests,
# and verifies detected alerts using verify_nids.py.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LAB_DIR="${LAB_LOG_DIR:-$SCRIPT_DIR/logs}"
INTERFACE="${SURICATA_IFACE:-lo}"
TEST_ARG="${1:--99}"

COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_GREEN="\033[32m"
COLOR_CYAN="\033[36m"
COLOR_YELLOW="\033[33m"

echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"
echo -e "${COLOR_BOLD}           TestMyNIDS - Automated NIDS Lab Verification           ${COLOR_RESET}"
echo -e "${COLOR_CYAN}=================================================================${COLOR_RESET}"

# Prepare clean lab log directory
mkdir -p "$LAB_DIR"
rm -f "$LAB_DIR/eve.json" "$LAB_DIR/fast.log" "$LAB_DIR/report.json"

# 1. Start Local Test Resource Server (with optional SSH stub on port 2222)
echo -e "\n${COLOR_CYAN}[1/5] Starting Test Resource Server on port 8080...${COLOR_RESET}"
python3 "$PROJECT_ROOT/server/app.py" --port 8080 > "$LAB_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
  echo -e "\n${COLOR_YELLOW}[*] Cleaning up background processes...${COLOR_RESET}"
  if [ -n "$SURICATA_PID" ] && kill -0 "$SURICATA_PID" 2>/dev/null; then
    kill -INT "$SURICATA_PID" 2>/dev/null || true
    wait "$SURICATA_PID" 2>/dev/null || true
  fi
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# 2. Start Suricata NIDS
echo -e "${COLOR_CYAN}[2/5] Starting Suricata NIDS on interface '$INTERFACE'...${COLOR_RESET}"
suricata \
  -c "$SCRIPT_DIR/suricata.yaml" \
  -s "$SCRIPT_DIR/rules/tmnids.rules" \
  -i "$INTERFACE" \
  -l "$LAB_DIR" \
  --runmode single > "$LAB_DIR/suricata.log" 2>&1 &
SURICATA_PID=$!

# Wait for Suricata engine initialization
echo -e "${COLOR_CYAN}[3/5] Waiting for Suricata engine initialization...${COLOR_RESET}"
for i in {1..10}; do
  if [ -f "$LAB_DIR/eve.json" ]; then
    sleep 2
    break
  fi
  sleep 1
done

# 3. Execute tmNIDS Test Suite
echo -e "${COLOR_CYAN}[4/5] Executing tmNIDS test suite (Arguments: $TEST_ARG)...${COLOR_RESET}"
"$PROJECT_ROOT/tmNIDS" -t "127.0.0.1:8080" "$TEST_ARG" || true

# Allow packets to flush into Suricata log buffers
sleep 3

# 4. Stop Suricata cleanly to flush eve.json
echo -e "${COLOR_CYAN}[5/5] Stopping Suricata and processing alert logs...${COLOR_RESET}"
if kill -0 "$SURICATA_PID" 2>/dev/null; then
  kill -INT "$SURICATA_PID" 2>/dev/null || true
  wait "$SURICATA_PID" 2>/dev/null || true
fi

# Determine test IDs for verification
VERIFY_ARGS=()
if [[ "$TEST_ARG" =~ ^-([0-9]+)$ ]]; then
  TEST_NUM="${BASH_REMATCH[1]}"
  if [ "$TEST_NUM" -ne 99 ]; then
    VERIFY_ARGS=(--tests "$TEST_NUM")
  fi
fi

# 5. Run Verification Engine
python3 "$SCRIPT_DIR/verify_nids.py" --eve "$LAB_DIR/eve.json" --json-out "$LAB_DIR/report.json" "${VERIFY_ARGS[@]}"

echo -e "\n${COLOR_GREEN}[+] Lab test run complete!${COLOR_RESET}"
echo -e "    Eve Log:      ${COLOR_BOLD}$LAB_DIR/eve.json${COLOR_RESET}"
echo -e "    JSON Report:  ${COLOR_BOLD}$LAB_DIR/report.json${COLOR_RESET}"
echo -e "    Suricata Log: ${COLOR_BOLD}$LAB_DIR/suricata.log${COLOR_RESET}"
echo -e "    Server Log:   ${COLOR_BOLD}$LAB_DIR/server.log${COLOR_RESET}\n"
