//see LICENSE for license
// The following is a RISC-V program to test the functionality of the
// sha3 RoCC accelerator.
// Compile with riscv-gcc sha3-rocc.c
// Run with spike --extension=sha3 pk a.out

#include <stdio.h>
#include <stdint.h>
#include "rocc.h"
//#include "sha3.h"
#include "encoding.h"
#include "compiler.h"

#ifdef __linuxlinux
#include <sys/mman.h>
#endif

int main() {

  unsigned long start, end;

//#ifdef __linux
  // Ensure all pages are resident to avoid accelerator page faults
//  if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
//    perror("mlockall");
//    return 1;
//  }
//#endif

     printf("Start basic test 1.\n");
    // BASIC TEST 1 - 150 zero bytes

    // Setup some test data
    static unsigned long input[32] __aligned(8) = {  0x0041000100400000, 0x0043000300420002, 0x0045000500440004, 0x0047000700460006,
    						       0x0049000900480008, 0x004B000B004A000A, 0x004D000D004C000C, 0x004F000F004E000E, 
    						       0x0051001100500010, 0x0053001300520012, 0x0055001500540014, 0x0057001700560016, 
    						       0x0059001900580018, 0x005B001B005A001A, 0x005D001D005C001C, 0x005F001F005E001E, 
    						       0x0061002100600020, 0x0063002300620022, 0x0065002500640024, 0x0067002700660026, 
    						       0x0069002900680028, 0x006B002B006A002A, 0x006D002D006C002C, 0x006F002F006E002E, 
    						       0x0071003100700030, 0x0073003300720032, 0x0075003500740034, 0x0077003700760036, 
    						       0x0079003900780038, 0x007B003B007A003A, 0x007D003D007C003C, 0x007F003F007E003E};
    static const unsigned long result[32] =
   {0x01380a2507550b3f, 0x02e80bca0bd30b5a, 0x089a0b0801cd0a5a, 0x019908c202b20099,
    0x0abd0b9e0098059d, 0x003309c805980964, 0x0362078307d509a2, 0x0ba70ac6047203f4,
    0x08c302e505d50b23, 0x08e500c802320891, 0x05bb03d4053402b0, 0x04810a390c290596,
    0x09cb04ac05dc06ee, 0x0af304eb0790020f, 0x003f003f01a306f8, 0x01450b9d01d60650,
    0x05fd0a4f04500517, 0x0a500b5006a005da, 0x00b909f6058706b1, 0x087c0b1e04bd0834,
    0x027d003508f1077b, 0x056a03650a5503b1, 0x0cbe032e088e0c8c, 0x06cf0a6c0cbe07c8,
    0x01500b6e013d0494, 0x0c7a08c70913006c, 0x049001f704020079, 0x003404440a7b033c,
    0x00060a66092a0837, 0x09ad09b306460988, 0x0bcf01d001f50183, 0x0bcf04e305110c22};
    unsigned long output[32] __aligned(8);
    unsigned long output_inverted[32] __aligned(8);
    printf("Size of input %d \n", sizeof(input));
    printf("Address of input: %lx\n", &input);
    printf("Address of output: %lx\n", &output);
    start = rdcycle();

    // Compute hash with acceleratoraccelerator
    asm volatile ("fence");
    ROCC_INSTRUCTION_SS(2, &input, &output, 0);
    ROCC_INSTRUCTION_SS(2, sizeof(input), 0, 1);
    asm volatile ("fence" ::: "memory");

    end = rdcycle();

    // Check resultresult
    int i;

        for(i = 0; i < 32; i++){
            printf("output[%d] = %lx  result[%d] = %lx\n",i,output[i], i, result[i] );
            if(output[i] != result[i]) {
                printf("Failed: Outputs don't match!\n");
                printf("NTT execution took %lu cycles\n", end - start);
                return 1;
            }
        }
      printf("Success!\n");
      printf("NTT execution took %lu cycles\n", end - start);

    printf("Start INTT\n");
    printf("Size of input %d \n", sizeof(output));
    printf("Address of input_inverted: %lx\n", &output);
    printf("Address of output_inverted: %lx\n", &output_inverted);

    start = rdcycle();
    asm volatile ("fence");
    ROCC_INSTRUCTION_SS(2, &output, &output_inverted, 0);
    ROCC_INSTRUCTION_SS(2, sizeof(output), 1, 1);
    asm volatile ("fence" ::: "memory");
    end = rdcycle();


    for(i = 0; i < 32; i++){
      printf("output[%d] = %lx  result[%d] = %lx\n",i,output_inverted[i], i, input[i] );
      if(output_inverted[i] != input[i]) {
        printf("Failed: Outputs don't match!\n");
        printf("INTT execution took %lu cycles\n", end - start);
        return 1;
        }
    }
    printf("Success!\n");
    printf("INTT execution took %lu cycles\n", end - start);
      return 0;
 }
