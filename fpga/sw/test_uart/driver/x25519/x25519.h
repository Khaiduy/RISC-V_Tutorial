#include <stdint.h>
#include "platform.h"
//#include "kprintf.h"
#include <string.h>

/* Register offsets */
#define X25519_REG_SCALAR               0x00
#define X25519_REG_POINT_IN             0x20
#define X25519_REG_POINT_OUT            0x40
#define X25519_REG_CONTROL              0x60
#define X25519_REG_STATUS               0x64

/* Control register bits */
#define X25519_CTRL_START               0x01
#define X25519_CTRL_RESET               0x02

/* Status register bits */
#define X25519_STATUS_START             0x01
#define X25519_STATUS_VALID             0x02

#define REG32(p, i) ((p)[(i) >> 2])
#define _REG64(p, i) (*(volatile uint64_t *)((p) + (i)))
#define _REG32(p, i) (*(volatile uint32_t *)((p) + (i)))
#define _REG16(p, i) (*(volatile uint16_t *)((p) + (i)))

#define X25519_CTRL_ADDR _AC(0x64004000,UL)
#define X25519_CTRL_SIZE _AC(0x1000,UL)
static volatile uint64_t * const x25519 = (void *)(X25519_CTRL_ADDR);
extern uintptr_t X25519_reg;

/* Function declarations */
void hwx25519_init(void* x25519ctrl, uint64_t scalar[4], uint64_t point_in[4]);
void hwx25519_results(void* x25519ctrl, uint64_t* result);
void hwx25519_reset(void* x25519ctrl);
void hwx25519_selftest(void* x25519ctrl);

void print_x25519_value(const char* label, uint64_t* value);  // Optional helper