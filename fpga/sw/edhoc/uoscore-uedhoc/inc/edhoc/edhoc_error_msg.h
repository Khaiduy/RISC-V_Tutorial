/*
 * edhoc_error_msg.h - EDHOC wire-format error messages per RFC 9528 §6
 *
 *   error = (
 *     ERR_CODE : int,
 *     ERR_INFO : any,
 *   )
 *
 * Encoded as a CBOR Sequence. Direct byte-level CBOR encoding avoids the
 * zcbor-generated edhoc_encode_message_error.c (which does not include
 * ERR_CODE per RFC 9528).
 */
#ifndef EDHOC_ERROR_MSG_H
#define EDHOC_ERROR_MSG_H

#include <stdint.h>
#include <stdbool.h>
#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"

/* RFC 9528 §6 Table 3 wire-format error codes. */
#define EDHOC_ERR_CODE_SUCCESS            0  /* internal only */
#define EDHOC_ERR_CODE_UNSPECIFIED        1
#define EDHOC_ERR_CODE_WRONG_CIPHER_SUITE 2
#define EDHOC_ERR_CODE_UNKNOWN_CRED       3

/**
 * @brief Map an internal err enum to a wire-format ERR_CODE per RFC 9528 §6.
 */
int edhoc_map_to_wire_err_code(enum err internal);

/**
 * @brief Build a CBOR-Sequence error message: (ERR_CODE: int, ERR_INFO: any).
 *
 * ERR_INFO contents per RFC 9528 §6:
 *  - ERR_CODE=1: tstr (diagnostic)        → pass utf-8 bytes in diag/diag_len
 *  - ERR_CODE=2: suites_r (int or array)  → pass pre-encoded CBOR in info_cbor
 *  - ERR_CODE=3: true                     → caller passes NULL/0 (we emit 0xF5)
 *
 * Exactly one of (diag, info_cbor) should be non-NULL based on err_code.
 *
 * @param[out] out      output buffer (caller-supplied)
 * @param      out_max  output buffer capacity
 * @param      err_code wire ERR_CODE
 * @param      diag     diagnostic tstr bytes (for ERR_CODE=1); NULL otherwise
 * @param      diag_len length of diag (0 if NULL)
 * @param      info_cbor pre-encoded CBOR bytes for ERR_INFO (for ERR_CODE=2);
 *                       NULL otherwise
 * @param      info_cbor_len length of info_cbor (0 if NULL)
 * @param[out] out_len  bytes written to out
 */
enum err edhoc_build_error_message(uint8_t *out, uint32_t out_max,
                                   int err_code,
                                   const char *diag, uint32_t diag_len,
                                   const uint8_t *info_cbor, uint32_t info_cbor_len,
                                   uint32_t *out_len);

/**
 * @brief Heuristic check: does buf look like an EDHOC error message?
 *
 * Per RFC §6, error starts with int (CBOR major type 0 or 1). msg_2/3/4
 * all start with bstr (major type 2). msg_1 also starts with int but
 * an initiator never *receives* msg_1, so disambiguation is fine.
 */
bool edhoc_is_error_message(const uint8_t *buf, uint32_t len);

/**
 * @brief Parse an EDHOC wire-format error message.
 *
 * @param      buf       received CBOR sequence
 * @param      buf_len   length of buf
 * @param[out] err_code  decoded ERR_CODE
 * @param[out] err_info  pointer + length of ERR_INFO inside buf (no copy)
 */
enum err edhoc_parse_error_message(const uint8_t *buf, uint32_t buf_len,
                                   int *err_code,
                                   struct const_byte_array *err_info);

#endif /* EDHOC_ERROR_MSG_H */
