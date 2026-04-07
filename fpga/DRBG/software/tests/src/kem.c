#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
//#include "randombytes.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(uint8_t *pk,
                       uint8_t *sk)
{
  uint8_t z_rand[KYBER_SYMBYTES] = {
    0x3e, 0x2a, 0x2e, 0xa6, 0xc9, 0xc4, 0x76, 0xfc,
    0x49, 0x37, 0xb0, 0x13, 0xc9, 0x93, 0xa7, 0x93,
    0xd6, 0xc0, 0xab, 0x99, 0x60, 0x69, 0x5b, 0xa8,
    0x38, 0xf6, 0x49, 0xda, 0x53, 0x9c, 0xa3, 0xd0
  };
  size_t i;
  indcpa_keypair(pk, sk);
  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES); //hash_h(*out, *in, outlen)
  /* Value z for pseudo-random output on reject */
  //randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES); // comment when run on RISCV
  for(i=0; i<KYBER_SYMBYTES; i++){
    sk[KYBER_SECRETKEYBYTES-KYBER_SYMBYTES + i] = z_rand[i];
  }
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - uint8_t *ct: pointer to output cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(uint8_t *ct,
                   uint8_t *ss,
                   const uint8_t *pk)
{
//  uint8_t buf[2*KYBER_SYMBYTES];
  uint8_t buf[2*KYBER_SYMBYTES]={
    0xba, 0xc5, 0xba, 0x88, 0x1d, 0xd3, 0x5c, 0x59,
    0x71, 0x96, 0x70, 0x00, 0x46, 0x92, 0xd6, 0x75,
    0xb8, 0x3c, 0x98, 0xdb, 0x6a, 0x0e, 0x55, 0x80,
    0x0b, 0xaf, 0xeb, 0x7e, 0x70, 0x49, 0x1b, 0xf4,

    0x4e, 0x3a, 0x3e, 0xb6, 0xd9, 0xd4, 0x86, 0x0c,
    0x59, 0x47, 0xc0, 0x23, 0xd9, 0x03, 0xb7, 0xa3,
    0xe6, 0xd0, 0xbb, 0x09, 0x70, 0x79, 0x6b, 0xb8,
    0x48, 0x06, 0x59, 0xea, 0x63, 0x0c, 0xb3, 0xe0
  };
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  //randombytes(buf, KYBER_SYMBYTES); // comment when using riscv
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);     // sha3-256 -> gen random m, comment when m is known

//  printf("\n=================== MESSAGE ===================\n");
//  for (int i = 0; i < KYBER_SYMBYTES; i++) {
//    printf("%02x", buf[i]);
//    if ((i + 1) % 32 == 0) printf("\n");
//  }

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);     // H(pk) = H(ek)
  hash_g(kr, buf, 2*KYBER_SYMBYTES);                        // (K,r) = G(m||H(ek))

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - uint8_t *ss: pointer to output shared secret
*                (an already allocated array of KYBER_SSBYTES bytes)
*              - const uint8_t *ct: pointer to input cipher text
*                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
*              - const uint8_t *sk: pointer to input private key
*                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(uint8_t *ss,
                   const uint8_t *ct,
                   const uint8_t *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}
