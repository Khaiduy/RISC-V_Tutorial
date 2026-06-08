# EDHOC Hardware Timing Runs — Build & Upload

Four configs for timing measurement on the two-board Arty + C232HM JTAG setup:

| Config | Method | Suite | Crypto |
|--------|--------|-------|--------|
| M3 S0  | 3 (StaticDH/StaticDH) | 0 | X25519 + AES-CCM + SHA-256 |
| M3 S7  | 3 (StaticDH/StaticDH) | 7 | X25519 + Ascon-AEAD + Ascon-Hash |
| PSK S0 | 4 (PSK)               | 0 | AES-CCM + SHA-256 |
| PSK S7 | 4 (PSK)               | 7 | Ascon-AEAD + Ascon-Hash |

All built with `TIMING=1` (defines `TIMING_BREAKDOWN` → per-phase cycle prints) and the
legacy backend for Suite 7 / PSK (Monocypher + TinyCrypt + Ascon-c — smaller and faster
than wolfCrypt).

Toolchain: `/home/khaiduy/opt/riscv/bin/riscv64-unknown-elf-gcc` (RV32IMAC).

---

## 1. Build

From `fpga/sw/edhoc/`:

```bash
# --- M3 Suite 0 (wolfCrypt backend) ---
make edhoc_m3_responder CRYPTO_SUITE=0 TIMING=1
make edhoc_m3_initiator CRYPTO_SUITE=0 TIMING=1
cp build/edhoc_m3_initiator.elf build/m3_s0_init.elf
cp build/edhoc_m3_responder.elf build/m3_s0_resp.elf

# --- M3 Suite 7 (legacy: Monocypher X25519 + Ascon-c) ---
make edhoc_m3_responder CRYPTO_SUITE=7 TIMING=1 EDHOC_BACKEND=legacy
make edhoc_m3_initiator CRYPTO_SUITE=7 TIMING=1 EDHOC_BACKEND=legacy
cp build/edhoc_m3_initiator.elf build/m3_s7_init.elf
cp build/edhoc_m3_responder.elf build/m3_s7_resp.elf

# --- PSK Suite 0 (legacy: TinyCrypt AES-CCM + SHA-256) ---
make edhoc_psk_responder_legacy CRYPTO_SUITE=0 TIMING=1 EDHOC_BACKEND=legacy
make edhoc_psk_initiator_legacy CRYPTO_SUITE=0 TIMING=1 EDHOC_BACKEND=legacy
cp build/edhoc_psk_initiator.elf build/psk_s0_init.elf
cp build/edhoc_psk_responder.elf build/psk_s0_resp.elf

# --- PSK Suite 7 (legacy: Ascon-c) ---
make edhoc_psk_responder_legacy CRYPTO_SUITE=7 TIMING=1 EDHOC_BACKEND=legacy
make edhoc_psk_initiator_legacy CRYPTO_SUITE=7 TIMING=1 EDHOC_BACKEND=legacy
cp build/edhoc_psk_initiator.elf build/psk_s7_init.elf
cp build/edhoc_psk_responder.elf build/psk_s7_resp.elf
```

Each `make` target rebuilds the matching EDHOC library (M3 → `uoscore-uedhoc/`,
PSK → `uoscore-uedhoc-psk/`) then links the app. The `cp` lines snapshot each
config under a stable name so they don't get overwritten by the next build.

Built ELF sizes (text): M3 ≈ 25 kB, PSK ≈ 21–24 kB. All fit the 16 kB+ scratchpad
config (`SmallRocket32...`).

---

## 2. Upload + Run (two boards via C232HM JTAG)

Hardware:
- Board A (Initiator): C232HM `FTA6JVAK`, UART `/dev/ttyUSB3`
- Board B (Responder): C232HM `FTA6GPSN`, UART `/dev/ttyUSB5`
- JTAG on PMOD JD (TCK=JD2, TDI=JD0, TDO=JD3, TMS=JD1, GND)

From `fpga/sw/test_uart/`, pass the two ELFs via env vars and the
method+suite as positional args:

```bash
# M3 S0
INITIATOR_ELF=../edhoc/build/m3_s0_init.elf \
RESPONDER_ELF=../edhoc/build/m3_s0_resp.elf \
  ./load_edhoc.sh 3 0

# M3 S7
INITIATOR_ELF=../edhoc/build/m3_s7_init.elf \
RESPONDER_ELF=../edhoc/build/m3_s7_resp.elf \
  ./load_edhoc.sh 3 7

# PSK S0  (method arg 4 = PSK)
INITIATOR_ELF=../edhoc/build/psk_s0_init.elf \
RESPONDER_ELF=../edhoc/build/psk_s0_resp.elf \
  ./load_edhoc.sh 4 0

# PSK S7
INITIATOR_ELF=../edhoc/build/psk_s7_init.elf \
RESPONDER_ELF=../edhoc/build/psk_s7_resp.elf \
  ./load_edhoc.sh 4 7
```

The script: starts OpenOCD on both adapters, holds the UARTs open, loads each ELF
over telnet (`load_image` + `resume 0x80000000`), waits for `EDHOC OK` / `EDHOC FAIL`
in the logs, then prints both boards' output. Logs are saved to
`/tmp/edhoc_<timestamp>/{initiator,responder}.log`.

Timing lines (cycles per phase) appear in the captured output because the ELFs were
built with `TIMING=1`. The **responder log is authoritative** — the initiator board
is known to drop some UART bytes.

---

## 3. JTAG notes (lessons learned)

- The C232HM adapters run at **`adapter speed 100`** (kHz) in
  `c232hm_board_initiator.cfg` / `c232hm_board_responder.cfg`. 1000 kHz gave
  `dmstatus=0x0` "JTAG signal issue" errors on the flying-lead cables.
- `load_edhoc.sh` waits **8 s** after starting OpenOCD (was 3 s) so both cores
  finish examine before the telnet `halt`.
- If you still see `Failed read (NOP) at 0x11; status=1` then `dmstatus=0x0` spam:
  it's JTAG signal integrity (usually responder cable). Reseat the C232HM leads and
  GND on PMOD JD, or swap the two cables to see if the fault follows the cable.
  Probe a single board to confirm health:
  ```bash
  openocd -f c232hm_board_responder.cfg -c "shutdown"
  # expect: "Examined RISC-V core; found 1 harts ... board halted"
  ```
