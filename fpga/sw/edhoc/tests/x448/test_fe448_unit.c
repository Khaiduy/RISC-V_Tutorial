/*
 * fe448 field-arithmetic unit tests — isolate bugs before the ladder.
 * Exposes the static fe448 ops by #including monocypher.c directly (test-only).
 *
 * Build (from fpga/sw/edhoc/):
 *   gcc -O0 -g -Wall -I uoscore-uedhoc/externals/Monocypher/src \
 *       tests/x448/test_fe448_unit.c -o /tmp/fe448 && /tmp/fe448
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Pull in the implementation (static fe448 ops become visible). */
#include "monocypher.c"

static int fails = 0;
#define CHECK(c,n) do{ if(c) printf("[PASS] %s\n",n); else {printf("[FAIL] %s\n",n); fails++;} }while(0)

static int fe_eq(const fe448 a, const fe448 b){
	u8 sa[56], sb[56]; fe448_tobytes(sa,(u64*)a); fe448_tobytes(sb,(u64*)b);
	return memcmp(sa,sb,56)==0;
}
static void prfe(const char*l,const fe448 a){ u8 s[56]; fe448_tobytes(s,(u64*)a);
	printf("%s",l); for(int i=0;i<56;i++)printf("%02x",s[i]); printf("\n"); }

int main(void){
	printf("=== fe448 unit tests ===\n");
	fe448 a,b,c,one,tmp;
	fe448_1(one);

	fe448_0(a); a[0]=7;

	fe448_mul(c,a,one);
	CHECK(fe_eq(c,a), "a*1 == a");
	if(!fe_eq(c,a)){ prfe(" a: ",a); prfe(" c: ",c); }

	fe448_mul(c,one,one);
	CHECK(fe_eq(c,one), "1*1 == 1");

	fe448_0(b); fe448_add(c,a,b); fe448_carry(c);
	CHECK(fe_eq(c,a), "a+0 == a");

	fe448_0(b); b[0]=12345;
	fe448_mul(c,a,b); fe448_mul(tmp,b,a);
	CHECK(fe_eq(c,tmp), "a*b == b*a");

	fe448 P; FOR(i,0,16) P[i]=FE448_P[i];
	fe448_sub(tmp,P,a); fe448_carry(tmp);
	fe448_add(c,tmp,a); fe448_carry(c);
	fe448 zero; fe448_0(zero);
	CHECK(fe_eq(c,zero), "(p-a)+a == 0");
	if(!fe_eq(c,zero)) prfe(" c: ",c);

	fe448_invert(tmp,a);
	fe448_mul(c,a,tmp);
	CHECK(fe_eq(c,one), "a*inv(a) == 1");
	if(!fe_eq(c,one)) prfe(" c: ",c);

	fe448_sq(c,a); fe448_mul(tmp,a,a);
	CHECK(fe_eq(c,tmp), "sq(a) == a*a");

	u8 in[56], out[56];
	for(int i=0;i<56;i++) in[i]=(u8)(i*7+1);
	in[55] &= 0x7f;
	fe448 f; fe448_frombytes(f,in); fe448_tobytes(out,f);
	CHECK(memcmp(in,out,55)==0, "frombytes/tobytes round-trip (low 55 bytes)");

	printf("\n%s (%d failures)\n", fails?"=== FAILURES ===":"=== ALL PASS ===", fails);
	return fails?1:0;
}
