#include "edhoc_transport.h"
#include "kprintf.h"

enum err ead_process(void *params, struct byte_array *ead) {
    (void)params;
    (void)ead;
    return ok;
}

enum err tx_initiator(void *sock, struct byte_array *data) {
    (void)sock;
    uart1_putc((data->len >> 8) & 0xFF);
    uart1_putc(data->len & 0xFF);
    for (uint32_t i = 0; i < data->len; i++) {
        uart1_putc(data->ptr[i]);
        for (volatile int d = 0; d < 50000; d++);
    }
#ifdef DEBUG_PRINT
    /* Single end-of-call print — fewer kprintf transitions = less FT2232H byte loss */
    kprintf("[I-TX] sent %d bytes\r\n", data->len);
#endif
    return ok;
}

enum err rx_initiator(void *sock, struct byte_array *data) {
    (void)sock;
    int timeout = 1000000000, c;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
#ifdef DEBUG_PRINT
        kprintf("[I-RX] TIMEOUT len1\r\n");
#endif
        return transport_deinitialized;
    }
    uint32_t len = c << 8;
    timeout = 100000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
#ifdef DEBUG_PRINT
        kprintf("[I-RX] TIMEOUT len2\r\n");
#endif
        return transport_deinitialized;
    }
    len |= c;
    if (len > data->len) {
#ifdef DEBUG_PRINT
        kprintf("[I-RX] Buffer too small (%u > %u)\r\n", (unsigned)len, (unsigned)data->len);
#endif
        return buffer_to_small;
    }
    for (uint32_t i = 0; i < len; i++) {
        timeout = 100000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) {
#ifdef DEBUG_PRINT
            kprintf("[I-RX] TIMEOUT byte %d/%u\r\n", i, (unsigned)len);
#endif
            return transport_deinitialized;
        }
        data->ptr[i] = c;
    }
    data->len = len;
#ifdef DEBUG_PRINT
    /* Single end-of-call print */
    kprintf("[I-RX] got %u bytes\r\n", (unsigned)len);
#endif
    return ok;
}

enum err tx_responder(void *sock, struct byte_array *data) {
    (void)sock;
    uart1_putc((data->len >> 8) & 0xFF);
    uart1_putc(data->len & 0xFF);
    for (uint32_t i = 0; i < data->len; i++) {
        uart1_putc(data->ptr[i]);
        for (volatile int d = 0; d < 50000; d++);
    }
#ifdef DEBUG_PRINT
    kprintf("[R-TX] sent %d bytes\r\n", data->len);
#endif
    return ok;
}

enum err rx_responder(void *sock, struct byte_array *data) {
    (void)sock;
    int timeout, c;
    /* Wait indefinitely for first byte of length prefix from initiator.
     * SW-crypto initiator may take several seconds for key generation. */
    while ((c = uart1_getc()) < 0);
    uint32_t len = c << 8;
    timeout = 10000000;
    while ((c = uart1_getc()) < 0 && timeout-- > 0);
    if (c < 0) {
#ifdef DEBUG_PRINT
        kprintf("[R-RX] TIMEOUT len2\r\n");
#endif
        return transport_deinitialized;
    }
    len |= c;
    if (len > data->len) {
#ifdef DEBUG_PRINT
        kprintf("[R-RX] Buffer too small (%u > %u)\r\n", (unsigned)len, (unsigned)data->len);
#endif
        return buffer_to_small;
    }
    for (uint32_t i = 0; i < len; i++) {
        timeout = 10000000;
        while ((c = uart1_getc()) < 0 && timeout-- > 0);
        if (c < 0) {
#ifdef DEBUG_PRINT
            kprintf("[R-RX] TIMEOUT byte %d/%u\r\n", i, (unsigned)len);
#endif
            return transport_deinitialized;
        }
        data->ptr[i] = c;
    }
    data->len = len;
#ifdef DEBUG_PRINT
    kprintf("[R-RX] got %u bytes\r\n", (unsigned)len);
#endif
    return ok;
}
