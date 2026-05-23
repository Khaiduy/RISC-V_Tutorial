#!/bin/bash
# load_edhoc.sh — Load and start both EDHOC boards via C232HM external JTAG
# Board A (Initiator): C232HM on PMOD JD, UART terminal /dev/ttyUSB1
# Board B (Responder): C232HM on PMOD JD, UART terminal /dev/ttyUSB2

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EDHOC_DIR="$(realpath "$SCRIPT_DIR/../edhoc")"

# Positional args: load_edhoc.sh [METHOD] [SUITE]
METHOD="${1:-${METHOD:-0}}"
SUITE="${2:-${SUITE:-0}}"
INITIATOR_ELF="${INITIATOR_ELF:-$EDHOC_DIR/build/edhoc_m${METHOD}_initiator.elf}"
RESPONDER_ELF="${RESPONDER_ELF:-$EDHOC_DIR/build/edhoc_m${METHOD}_responder.elf}"

# Suite 24 (P-384) and Suite 25 (X448/Ed448) are slow on bare-metal RV32I.
# P-384 key gen can take several minutes; use 600s per board.
if [ "$SUITE" = "24" ] || [ "$SUITE" = "25" ]; then
    BOARD_TIMEOUT=60
else
    BOARD_TIMEOUT=60
fi

INITIATOR_CFG="$SCRIPT_DIR/c232hm_board_initiator.cfg"
RESPONDER_CFG="$SCRIPT_DIR/c232hm_board_responder.cfg"

INITIATOR_UART="${INITIATOR_UART:-/dev/ttyUSB1}"
RESPONDER_UART="${RESPONDER_UART:-/dev/ttyUSB2}"

INITIATOR_TELNET=4444
RESPONDER_TELNET=4445

# --- Cleanup: registered first so any exit (error or Ctrl-C) tears down cleanly ---
OPENOCD_INIT_PID=
OPENOCD_RESP_PID=
UART_INIT_PID=
UART_RESP_PID=

cleanup() {
    echo ""
    echo "=== Cleaning up and exiting ==="
    [[ -n "$OPENOCD_INIT_PID" ]] && kill "$OPENOCD_INIT_PID" 2>/dev/null || true
    [[ -n "$OPENOCD_RESP_PID" ]] && kill "$OPENOCD_RESP_PID" 2>/dev/null || true
    [[ -n "$UART_INIT_PID"    ]] && kill "$UART_INIT_PID"    2>/dev/null || true
    [[ -n "$UART_RESP_PID"    ]] && kill "$UART_RESP_PID"    2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- Hardware / OS Optimization Functions ---
optimize_uart() {
    local uart_path=$1
    echo "  Configuring $uart_path to RAW mode..."
    # Disable all kernel processing to ensure perfect binary/hex transfers
    stty -F "$uart_path" 57600 raw -echo -echoe -echok -echoctl -echoke \
         -ignbrk -brkint -icrnl -imaxbel -opost -onlcr \
         -isig -icanon -iexten clocal -crtscts 2>/dev/null || true

    # Attempt to lower FTDI latency timer for snappier responses (like Minicom)
    # Fails silently if no sudo access
    local dev_name
    dev_name=$(basename "$uart_path")
    if [ -w "/sys/class/tty/$dev_name/device/latency_timer" ]; then
        echo 1 > "/sys/class/tty/$dev_name/device/latency_timer" 2>/dev/null || true
    elif [ -e "/sys/class/tty/$dev_name/device/latency_timer" ]; then
        echo 1 | sudo -n tee "/sys/class/tty/$dev_name/device/latency_timer" > /dev/null 2>/dev/null || true
    fi
}

flush_uart_input() {
    local uart_path=$1
    python3 - "$uart_path" <<'PY'
import os, sys, termios
uart_path = sys.argv[1]
try:
    fd = os.open(uart_path, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    termios.tcflush(fd, termios.TCIFLUSH)
    os.close(fd)
except Exception:
    pass
PY
}

# --- High-Speed Capture Function ---
# Captures UART to log file only (no live terminal output).
# Sequential display happens after both boards finish.
start_uart_capture() {
    local uart_path=$1
    local log_path=$2
    stdbuf -i0 -o0 cat "$uart_path" >> "$log_path"
}

# Poll a log file until a terminal marker appears or timeout expires.
wait_for_done() {
    local log_path=$1
    local label=$2
    local timeout=${3:-120}
    local elapsed=0
    printf "  Waiting for %s to finish" "$label"
    while ! grep -qE "EDHOC OK|EDHOC FAIL" "$log_path" 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        printf "."
        if [ "$elapsed" -ge "$timeout" ]; then
            printf " TIMEOUT\n"
            return 1
        fi
    done
    printf " done\n"
    return 0
}

# Print a log file with a label prefix on each line.
display_log() {
    local log_path=$1
    local label=$2
    echo ""
    echo "=== $label output ==="
    sed "s/^/$label /" "$log_path"
    echo "=== end $label ==="
}


echo "=== EDHOC Two-Board Loader (C232HM external JTAG) ==="
echo "Initiator ELF : $INITIATOR_ELF"
echo "Responder ELF : $RESPONDER_ELF"
echo "Initiator UART: $INITIATOR_UART"
echo "Responder UART: $RESPONDER_UART"
echo ""

# --- 1. Kill any stale OpenOCD and UART holders ---
echo "[1/5] Killing any stale OpenOCD and UART port holders..."
pkill -9 -f openocd 2>/dev/null || true
fuser -k "$INITIATOR_UART" 2>/dev/null || true
fuser -k "$RESPONDER_UART" 2>/dev/null || true
sleep 1
# --- 2. Prepare log directory ---
LOG_DIR="/tmp/edhoc_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"
echo "[2/5] Log directory created: $LOG_DIR"
# (Notice we removed optimize_uart from here)

# --- 3. Start OpenOCD for both boards ---
echo "[3/5] Starting OpenOCD instances..."
openocd -f "$INITIATOR_CFG" &> /tmp/openocd_initiator.log &
OPENOCD_INIT_PID=$!

openocd -f "$RESPONDER_CFG" &> /tmp/openocd_responder.log &
OPENOCD_RESP_PID=$!

echo "  Waiting for OpenOCD to connect..."
sleep 3

if ! kill -0 "$OPENOCD_INIT_PID" 2>/dev/null; then
    echo "ERROR: Initiator OpenOCD died. Check /tmp/openocd_initiator.log"
    exit 1
fi
if ! kill -0 "$OPENOCD_RESP_PID" 2>/dev/null; then
    echo "ERROR: Responder OpenOCD died. Check /tmp/openocd_responder.log"
    exit 1
fi

# --- 4. Start Silent Capture & HOLD PORTS OPEN ---
echo "[4/5] Starting silent capture (Holding ports open)..."
echo "  Logs: $LOG_DIR/initiator.log  $LOG_DIR/responder.log"

# Start the capture FIRST. This opens the port and holds it open.
start_uart_capture "$INITIATOR_UART" "$LOG_DIR/initiator.log" &
UART_INIT_PID=$!
start_uart_capture "$RESPONDER_UART" "$LOG_DIR/responder.log" &
UART_RESP_PID=$!

sleep 0.5 # Give the 'cat' commands a moment to latch onto the ports

# NOW optimize the UARTs. Because 'cat' is running, the ports are open, 
# and these 'stty' settings will NOT be forgotten by the kernel.
optimize_uart "$INITIATOR_UART"
optimize_uart "$RESPONDER_UART"

# --- 5. Halting boards and flushing ---
halt_board() {
    local port=$1 label=$2
    python3 - <<PYEOF
import socket, time, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', $port))
    s.settimeout(2)
    time.sleep(0.2)
    s.sendall(b'halt\n')
    time.sleep(0.2)
    s.close()
except Exception as exc:
    print(f'ERROR: failed to halt {label}: {exc}', file=sys.stderr)
    sys.exit(1)
PYEOF
}

echo "[5/5] Halting boards and flushing stale UART data..."
halt_board "$INITIATOR_TELNET" "initiator"
halt_board "$RESPONDER_TELNET" "responder"

# Flush any garbage that accumulated during the open/stty phase
flush_uart_input "$INITIATOR_UART"
flush_uart_input "$RESPONDER_UART"


# --- 6. Load ELFs via Telnet ---
load_via_telnet() {
    local port=$1 elf=$2 label=$3
    # We must pass the bash variables as arguments to the python interpreter
    python3 - "$port" "$elf" "$label" <<'PYEOF'
import socket, time, sys

port = int(sys.argv[1])
elf = sys.argv[2]
label = sys.argv[3]

def telnet_cmds(host, port, commands):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(2)
    time.sleep(0.3)
    try: s.recv(8192)
    except: pass
    results = []
    for cmd, wait in commands:
        s.settimeout(wait)
        s.sendall((cmd + '\n').encode())
        deadline = time.time() + wait
        buf = b''
        while time.time() < deadline:
            s.settimeout(max(0.1, deadline - time.time()))
            try:
                chunk = s.recv(4096)
                if not chunk: break
                buf += chunk
                if buf.rstrip().endswith(b'>'): break
            except socket.timeout: break
        results.append((cmd, buf.decode(errors='replace').strip()))
    s.close()
    return results

commands = [
    ('reset halt', 5.0),  # full peripheral reset (clears UART FIFOs from prior boot)
    ('halt', 2.0),
    ('reg mstatus 0x0', 1.0),
    ('reg mie 0x0', 1.0),
    ('reg mtvec 0x80000000', 1.0),
    (f'load_image {elf}', 90.0),
    ('resume 0x80000000', 2.0),
]

try:
    results = telnet_cmds('127.0.0.1', port, commands)
    for cmd, resp in results:
        if 'Error' in resp or 'error' in resp:
            print(f'\n  [FAIL] {label} error on {cmd!r}: {resp[:100]}', file=sys.stderr)
            sys.exit(1)
    sys.exit(0)
except Exception as e:
    print(f'\n  [FAIL] {label} connection error: {e}', file=sys.stderr)
    sys.exit(1)
PYEOF
}

echo "  Loading Responder ELF to Board B..."
load_via_telnet "$RESPONDER_TELNET" "$RESPONDER_ELF" "Responder"
sleep 0.5
echo "  Loading Initiator ELF to Board A..."
load_via_telnet "$INITIATOR_TELNET" "$INITIATOR_ELF" "Initiator"

echo "--------------------------------------------------------"
echo " Both boards running. Waiting for completion..."
echo "--------------------------------------------------------"

# Wait for each board to finish (up to 120s each), then display sequentially.
# Initiator log may be empty for fast methods (e.g. M3, MAC-only) if EDHOC
# completes before UART capture catches the output.  Use || true so set -e
# doesn't abort the script; the responder log is the authoritative result.
wait_for_done "$LOG_DIR/initiator.log" "Initiator" $BOARD_TIMEOUT || true
wait_for_done "$LOG_DIR/responder.log" "Responder" $BOARD_TIMEOUT

kill "$UART_INIT_PID" 2>/dev/null || true
kill "$UART_RESP_PID" 2>/dev/null || true

display_log "$LOG_DIR/initiator.log" "[INIT]"
display_log "$LOG_DIR/responder.log" "[RESP]"

echo ""
echo "Logs saved to: $LOG_DIR"