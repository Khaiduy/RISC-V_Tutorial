#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "symmetric.h"
#include "encoding.h"
//#include "randombytes.h"

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  poly_compress(r+KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_decompress(b, c);
  poly_decompress(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES) // (12*256/8*4096/3329 + 168)/168
// Not static for benchmarking
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed)
{
  unsigned int ctr, i, j, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    for(j=0;j<KYBER_K;j++) {
      if(transposed)
        xof_absorb(&state, seed, i, j);
      else
        xof_absorb(&state, seed, j, i);

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      while(ctr < KYBER_N) {
        off = buflen % 3;
        for(k = 0; k < off; k++)
          buf[k] = buf[buflen - off + k];
        xof_squeezeblocks(buf + off, 1, &state);
        buflen = off + XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
      }
    }
  }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
                              (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned long start, end;
  unsigned int i;
//  uint8_t buf[2*KYBER_SYMBYTES] = {
//      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
//      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
//      0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
//      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//
//      0xFF, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
//      0x89, 0x90, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
//      0x11, 0x42, 0x64, 0x86, 0x08, 0xca, 0xec, 0x0e,
//      0x02, 0x24, 0x46, 0x68, 0x80, 0xac, 0xce, 0xe0
//    };

  uint8_t buf[2*KYBER_SYMBYTES] = { // the seed from test vector file, riscv cannot run randombytes function
    0x93, 0x4d, 0x60, 0xb3, 0x56, 0x24, 0xd7, 0x40,
    0xb3, 0x0a, 0x7f, 0x22, 0x7a, 0xf2, 0xae, 0x7c,
    0x67, 0x8e, 0x4e, 0x04, 0xe1, 0x3c, 0x5f, 0x50,
    0x9e, 0xad, 0xe2, 0xb7, 0x9a, 0xea, 0x77, 0xe2,

    0x4e, 0x3a, 0x3e, 0xb6, 0xd9, 0xd4, 0x86, 0x0c,
    0x59, 0x47, 0xc0, 0x23, 0xd9, 0x03, 0xb7, 0xa3,
    0xe6, 0xd0, 0xbb, 0x09, 0x70, 0x79, 0x6b, 0xb8,
    0x48, 0x06, 0x59, 0xea, 0x63, 0x0c, 0xb3, 0xe0
 };


  //uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;                  // gán địa chỉ cho public seed: d randomness
  const uint8_t *noiseseed = buf+KYBER_SYMBYTES;    // gán địa chỉ cho noise seed: z randomness
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;

  //randombytes(buf, KYBER_SYMBYTES); // phải khai randombyte trước tại đây
  hash_g(buf, buf, KYBER_SYMBYTES);   // hash_g(out, in, outlen) = sha3-512(publicseed)

  gen_a(a, publicseed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
start = rdcycle();
//  polyvec_ntt(&skpv);
//  polyvec_ntt(&e);
  polyvec_ntt_rocc(&skpv);
  polyvec_ntt_rocc(&e);
end = rdcycle();
  printf("NTT_rocc execution took %lu cycles\n", end - start);
  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_rocc(&pkpv.vec[i], &a[i], &skpv);
//    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
   // poly_tomont(&pkpv.vec[i]);
  }

//  polyvec_add(&pkpv, &pkpv, &e);
polyvec_add_rocc(&pkpv, &pkpv, &e);
//start = rdcycle();
//  polyvec_reduce(&pkpv);
//end = rdcycle();
//printf("polyvec reduce execution took %lu cycles\n", end - start);
  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned long start, end;
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  uint8_t nonce = 0;
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);

  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta1(sp.vec+i, coins, nonce++);
  for(i=0;i<KYBER_K;i++)
    poly_getnoise_eta2(ep.vec+i, coins, nonce++);
  poly_getnoise_eta2(&epp, coins, nonce++);
start = rdcycle();
  polyvec_ntt_rocc(&sp);
end = rdcycle();
printf("NTT_rocc enc execution took %lu cycles\n", end - start);
  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
//    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
    polyvec_basemul_rocc(&b.vec[i], &at[i], &sp);
//  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);
polyvec_basemul_rocc(&v, &pkpv, &sp);
start = rdcycle();
//  polyvec_invntt_tomont(&b);
//  poly_invntt_tomont(&v);
  polyvec_invntt_rocc(&b);
  poly_invntt_rocc(&v);
end = rdcycle();
printf("INTT_rocc enc execution took %lu cycles\n", end - start);
  polyvec_add_rocc(&b, &b, &ep);
  poly_add_rocc(&v, &v, &epp);
  poly_add_rocc(&v, &v, &k);
//  polyvec_add(&b, &b, &ep);
//  poly_add(&v, &v, &epp);
//  poly_add(&v, &v, &k);
//start = rdcycle();
//  polyvec_reduce(&b);
//  poly_reduce(&v);
//end = rdcycle();
//printf("reduce enc execution took %lu cycles\n", end - start);
  pack_ciphertext(c, &b, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  unsigned long start, end;
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);
start = rdcycle();
  //polyvec_ntt(&b);
  polyvec_ntt_rocc(&b);
end = rdcycle();
printf("NTT_rocc dec execution took %lu cycles\n", end - start);
//  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  polyvec_basemul_rocc(&mp, &skpv, &b);
start = rdcycle();
//  poly_invntt_tomont(&mp);
  poly_invntt_rocc(&mp);
end = rdcycle();
printf("INTT_rocc dec execution took %lu cycles\n", end - start);
  poly_sub(&mp, &v, &mp);

//start = rdcycle();
//  poly_reduce(&mp);
//end = rdcycle();
//printf("reduce dec execution took %lu cycles\n", end - start);
  poly_tomsg(m, &mp);
}
