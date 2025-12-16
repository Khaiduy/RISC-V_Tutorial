#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
//#include <time.h>
#include <riscv-pk/encoding.h>
#include "platform.h"
#include "kprintf.h"
#include "uart.h"
//#include "x25519/x25519.h"
// #include "rocc.h"
#define REG32(p, i)	((p)[(i) >> 2])

// Add a large static array to make the binary bigger for testing SD card copy
const char large_data[8192] = {0};

void fill_large_data() {
    // Not needed since initialized
}

int main(int hartid, char **argv) {
    
  REG32(uart, UART_REG_TXCTRL) = UART_TXEN;
  kprintf("Hello from sd card\r\n");

  // Use the large data
  kprintf("Large data size: %l\r\n", sizeof(large_data));
  kprintf("Hello again\r\n");

//  // Run X25519 hardware selftest
//  kprintf("Starting X25519 hardware test...\r\n");
//  hwx25519_selftest((void*)X25519_CTRL_ADDR);
//  kprintf("X25519 test completed.\r\n");

  while (1);
  // dead code
  return 0;
}