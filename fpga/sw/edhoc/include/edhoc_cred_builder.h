#ifndef EDHOC_CRED_BUILDER_H
#define EDHOC_CRED_BUILDER_H

#include <stdint.h>

/* Maximum bytes a CCS credential can occupy (EC2/P-256 ~87 bytes, OKP ~80 bytes) */
#define CRED_BUF_MAX 100

/*
 * Build a CCS credential (CWT Claims Set) containing a COSE_Key.
 * Returns the number of bytes written to buf.
 *
 * crv selects the COSE_Key type per RFC 9053 and RFC 9528 §3.5.2:
 *   crv=1  (P-256)   -> kty=2 (EC2), compact y=false per RFC 9528 §3.7 / RFC 9053 §7.1.1
 *   crv=4  (X25519)  -> kty=1 (OKP)
 *   crv=6  (Ed25519) -> kty=1 (OKP)
 */
uint32_t build_ccs_credential(uint8_t *buf, const char *name,
                               const uint8_t *kid, uint32_t kid_len,
                               const uint8_t *pk, uint32_t pk_len, uint8_t crv);

#endif /* EDHOC_CRED_BUILDER_H */
