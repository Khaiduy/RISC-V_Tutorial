#include "edhoc_cred_builder.h"

/*
 * Build a CCS credential (CWT Claims Set) containing a COSE_Key.
 *
 * Output CBOR structure (RFC 9528 §3.5.2):
 *   {2: name, 8: {1: COSE_Key}}
 *
 * COSE_Key encoding (RFC 9053):
 *   crv=1 (P-256) -> EC2: map(5){kty=2, kid, crv=1, x, y=false}
 *                    y=false is the compact-encoding form per RFC 9528 §3.7
 *   crv=4/6 (OKP) -> OKP: map(4){kty=1, kid, crv, x}
 */
uint32_t build_ccs_credential(uint8_t *buf, const char *name,
                               const uint8_t *kid, uint32_t kid_len,
                               const uint8_t *pk, uint32_t pk_len, uint8_t crv) {
    uint8_t *p = buf;
    uint32_t name_len = 0;
    while (name[name_len]) name_len++;

    int is_ec2 = (crv == 1 || crv == 2);  /* P-256 (crv=1) and P-384 (crv=2) use EC2 (kty=2); OKP otherwise */

    /* Outer map: {2: name, 8: cnf} */
    *p++ = 0xa2;  /* map(2) */

    /* Key 2: subject name (text string) */
    *p++ = 0x02;
    *p++ = 0x60 + (uint8_t)name_len;
    for (uint32_t i = 0; i < name_len; i++) *p++ = name[i];

    /* Key 8: cnf claim */
    *p++ = 0x08;
    *p++ = 0xa1;  /* map(1) */

    /* cnf key 1: COSE_Key */
    *p++ = 0x01;

    if (is_ec2) {
        /* EC2 key: map(5) {kty=2, kid, crv, x, y=false} */
        *p++ = 0xa5;  /* map(5) */
        *p++ = 0x01;  /* label: kty (1) */
        *p++ = 0x02;  /* value: EC2 (2) */
    } else {
        /* OKP key: map(4) {kty=1, kid, crv, x} */
        *p++ = 0xa4;  /* map(4) */
        *p++ = 0x01;  /* label: kty (1) */
        *p++ = 0x01;  /* value: OKP (1) */
    }

    /* kid (label 2) */
    *p++ = 0x02;
    *p++ = 0x40 + (uint8_t)kid_len;
    for (uint32_t i = 0; i < kid_len; i++) *p++ = kid[i];

    /* crv (label -1 = 0x20) */
    *p++ = 0x20;
    *p++ = crv;  /* 1=P-256, 4=X25519, 6=Ed25519 */

    /* x (label -2 = 0x21) */
    *p++ = 0x21;
    *p++ = 0x58;  /* bytes with 1-byte length */
    *p++ = (uint8_t)pk_len;
    for (uint32_t i = 0; i < pk_len; i++) *p++ = pk[i];

    if (is_ec2) {
        /* y=false (label -3 = 0x22, CBOR false = 0xf4) per RFC 9528 §3.7 */
        *p++ = 0x22;
        *p++ = 0xf4;
    }

    return (uint32_t)(p - buf);
}
