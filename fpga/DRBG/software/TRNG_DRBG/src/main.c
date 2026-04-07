// #include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
//#include <stddef.h>

#include <time.h>
#include <riscv-pk/encoding.h>
#include "platform.h"
#include "kprintf.h"

#define REG_RESET       0x48
#define REG_ENABLE      0x08
#define REG_WRITE_DONE  0x10
#define REG_ADDRESS     0x18
#define REG_DATA_IN     0x20
#define REG_START       0x28
#define REG_MODE        0x30
#define REG_DATA_OUT    0x38
#define REG_DONE        0x40

#define MODE_TRNG       0x00
#define MODE_TRNG_DRBG  0x02
#define MODE_CPU_DRBG   0x01
#define MODE_GEN_NXT    0x03
  
void drbg_reset(void *drbgCtrl){
    _REG64((char *)drbgCtrl, REG_RESET) = 0x0000000000000001;
    for(int i = 0; i < 1000; i++){};
    _REG64((char *)drbgCtrl, REG_RESET) = 0x0000000000000000;
}

uint64_t drbg_read_data(void *drbgCtrl, uint8_t addr) {
   uint64_t read_data;
   _REG64((char *)drbgCtrl, REG_ADDRESS) = addr;
   for (uint8_t i = 0; i < 100; i++){}; // delay
   read_data = _REG64((char *)drbgCtrl, REG_DATA_OUT);
   return read_data;
}

void drbg_write_data(void *drbgCtrl, uint8_t addr, uint64_t data){
   _REG64((char *)drbgCtrl, REG_ADDRESS) = addr;
   _REG64((char *)drbgCtrl, REG_DATA_IN) = data;
   _REG64((char *)drbgCtrl, REG_ENABLE)     = 0x0000000000000001;
   _REG64((char *)drbgCtrl, REG_ENABLE)     = 0x0000000000000000;
}

int drbg_wait_done(void *drbgCtrl)
{
    if(_REG64((char *)drbgCtrl, REG_DONE) == 0x0000000000000001){
        return 0;
    }else{
        return -1;
    }
}

void test_trng(void *drbgCtrl, uint64_t *rns){
    drbg_reset(drbgCtrl);
    kprintf("TESTING READING SEED FROM TRNG\r\n");
    _REG64((char *)drbgCtrl, REG_MODE)   = 0x0000000000000000;
    _REG64((char *)drbgCtrl, REG_START)  = 0x0000000000000001;
    _REG64((char *)drbgCtrl, REG_START)  = 0x0000000000000000;
    while(drbg_wait_done(drbgCtrl)){};
    for (uint8_t i = 0; i < 8; i++){
        kprintf("Reading index %x...\r\n", i);
        rns[i] = drbg_read_data(drbgCtrl, i);
    }
    for (uint8_t i = 0; i < 8; i++){
        kprintf("Random seed [%x] is: 0x%lx\r\n",i, rns[i]);
    }
}

void test_write_data(void *drbgCtrl, uint64_t *seed, uint64_t *rns){
    drbg_reset(drbgCtrl);
    kprintf("TESTING WRITING SEED TO REGS\r\n");
    _REG64((char *)drbgCtrl, REG_MODE)   = 0x0000000000000001;
    _REG64((char *)drbgCtrl, REG_START)  = 0x0000000000000001;
    for (uint8_t i = 0; i < 100; i++){};
    _REG64((char *)drbgCtrl, REG_START)  = 0x0000000000000000;
    for (uint8_t i = 0; i < 6; i++){
        drbg_write_data(drbgCtrl, i, seed[i]);
    }
    _REG64((char *)drbgCtrl, REG_WRITE_DONE)  = 0x0000000000000001;
    for (uint8_t i = 0; i < 100; i++){};
    _REG64((char *)drbgCtrl, REG_WRITE_DONE)  = 0x0000000000000000;
    while(drbg_wait_done(drbgCtrl)){};
    for (uint8_t i = 0; i < 100; i++){};

    for (uint8_t i = 0; i < 4; i++){
        rns[i] = drbg_read_data(drbgCtrl, i);
    }
    kprintf("Random Seed is: ");
    for (uint8_t i = 0; i < 4; i++){
        kprintf("%lx ",rns[i]);
    }
}


uint64_t seed[6]={  0x36401940fa8b1fba, 0x91a1661f211d78a0, 0xb9389a74e5bccfec,
                    0xe8d766af1a6d3b14, 0x496f25b0f1301b4f, 0x501be30380a137eb};

uint64_t random_sequence[8];
uint64_t drbgCtrl = (uint64_t *)0x64004000;

int main(void){

//  test_trng(drbgCtrl, random_sequence);
test_write_data(drbgCtrl, seed, random_sequence);

//      drbg_reset(drbgCtrl);
//      _REG64((char *)drbgCtrl, REG_MODE)   = 0x0000000000000000;
//      _REG64((char *)drbgCtrl, REG_START)  = 0x0000000000000001;
//      _REG64((char *)drbgCtrl, REG_START)  = 0x0000000000000000;
//      while(drbg_wait_done(drbgCtrl)){};
//      for (uint8_t i = 0; i < 8; i++){
//          random_sequence[i] = drbg_read_data(drbgCtrl, i);
//          kprintf("Random seed [%x] is: 0x%lx\r\n",i, random_sequence[i]);
//      }

  while(1) {};
  return 0;
}
