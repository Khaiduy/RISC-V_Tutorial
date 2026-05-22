#ifndef EDHOC_TRANSPORT_H
#define EDHOC_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include "uart.h"
#include "edhoc.h"

#define UART1_BASE 0x64003000UL
#define REG32_UART1(i) (((volatile uint32_t *)UART1_BASE)[(i) >> 2])

static inline void uart1_putc(uint8_t c) {
    while ((int32_t)REG32_UART1(UART_REG_TXFIFO) < 0);
    REG32_UART1(UART_REG_TXFIFO) = c;
}

static inline int uart1_getc(void) {
    int32_t val = (int32_t)REG32_UART1(UART_REG_RXFIFO);
    return (val < 0) ? -1 : (val & 0xFF);
}

/* RV32-correct 64-bit cycle counter: hi-lo-hi loop prevents torn reads */
static inline uint64_t read_cycles(void) {
    uint32_t lo, hi, hi2;
    do {
        asm volatile ("rdcycleh %0" : "=r" (hi));
        asm volatile ("rdcycle  %0" : "=r" (lo));
        asm volatile ("rdcycleh %0" : "=r" (hi2));
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
}

/* Volatile wipe — compiler cannot elide this */
static inline void zeroize(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
}

enum err ead_process(void *params, struct byte_array *ead);
enum err tx_initiator(void *sock, struct byte_array *data);
enum err rx_initiator(void *sock, struct byte_array *data);
enum err tx_responder(void *sock, struct byte_array *data);
enum err rx_responder(void *sock, struct byte_array *data);

#endif /* EDHOC_TRANSPORT_H */
