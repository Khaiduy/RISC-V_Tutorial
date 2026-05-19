// See LICENSE.Sifive for license details.
#include <platform.h>
#include <smp.h>
#include "common.h"

  .section .text.init
  .option norvc
  .globl _prog_start
_prog_start:
  // perform boot if hart_0, otherwise sleep
  csrr s0, mhartid
  bne s0, zero, _stop
  csrw mie, zero    // Disable all M-mode interrupt enables (s2 may be non-zero from prior run)
  la t0, _trap_handler
  csrw mtvec, t0    // Set trap vector to safe handler (catches any stale pending interrupt)
  la sp, _ram_end        // Load address of _ram_end from linker script
  
  // Clear .bss section (required for static variables to be zero-initialized)
  la t0, _fbss
  la t1, _ebss
_clear_bss:
  bge t0, t1, _bss_done
  sw zero, 0(t0)      // RV32: use sw (store word) instead of sd
  addi t0, t0, 4      // RV32: increment by 4 bytes instead of 8
  j _clear_bss
_bss_done:

  //li sp, (PAYLOAD_DEST + 0xff0) // 0x80000ff0
  //li sp, (0x80000000 + 0xff0) // 0x80000ff0
  csrr a0, mhartid
  call main
  li s1, MEMORY_MEM_ADDR        // 0x80000000
  jr s1
_stop:
  wfi
_loopback:
  j _loopback

  .align 2
_trap_handler:
  // Minimal trap handler: clear mie + return (handles any stale pending interrupt on boot)
  csrw mie, zero
  csrw mstatus, zero
  mret
