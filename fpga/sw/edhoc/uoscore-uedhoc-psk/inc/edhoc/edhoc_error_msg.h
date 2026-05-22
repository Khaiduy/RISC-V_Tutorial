/*
 * edhoc_error_msg.h - EDHOC wire-format error messages per RFC 9528 §6
 *                     and EDHOC-PSK draft-ietf-lake-edhoc-psk-07 §9.
 *
 *   error = (
 *     ERR_CODE : int,
 *     ERR_INFO : any,
 *   )
 *
 * Encoded as a CBOR Sequence. Direct byte-level CBOR encoding avoids the
 * zcbor-generated edhoc_encode_message_error.c (which does not include
 * ERR_CODE per RFC 9528).
 *
 * ============================================================================
 * NOTE: This file is the PSK-library copy. The standard RFC 9528 library
 * (uoscore-uedhoc/) has its own copy. The two libraries are swap-deployed,
 * never linked together — do not cross-include.
 * ============================================================================
 *
 * EDHOC-PSK draft -07 §9 specialization:
 *   For Method 4 (PSK), all message_3 processing failures (AEAD failure,
 *   unknown credential, malformed input) MUST be externally indistinguishable
 *   from the perspective of an external observer. Callers handling msg_3
 *   failures in PSK mode SHOULD use edhoc_build_error_message_psk_uniform()
 *   which always emits the same ERR_CODE and the same opaque diagnostic.
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
 * For PSK msg_3 failures, callers should NOT use this — use the uniform helper.
 */
int edhoc_map_to_wire_err_code(enum err internal);

/**
 * @brief Build a CBOR-Sequence error message: (ERR_CODE: int, ERR_INFO: any).
 *
 * ERR_INFO contents per RFC 9528 §6:
 *  - ERR_CODE=1: tstr (diagnostic)        → pass utf-8 bytes in diag/diag_len
 *  - ERR_CODE=2: suites_r (int or array)  → pass pre-encoded CBOR in info_cbor
 *  - ERR_CODE=3: true                     → caller passes NULL/0 (we emit 0xF5)
 */
enum err edhoc_build_error_message(uint8_t *out, uint32_t out_max,
                                   int err_code,
                                   const char *diag, uint32_t diag_len,
                                   const uint8_t *info_cbor, uint32_t info_cbor_len,
                                   uint32_t *out_len);

/**
 * @brief PSK msg_3-failure helper.
 *
 * draft-ietf-lake-edhoc-psk-07 §9 mandates indistinguishable observable
 * behavior for ALL msg_3 processing failures in EDHOC-PSK (AEAD failure,
 * unknown credential, malformed input). This helper always emits the same
 * ERR_CODE=1 with a fixed opaque diagnostic, regardless of the underlying
 * cause, so an external observer cannot distinguish failure modes.
 *
 * Caller is also responsible for ensuring that the *timing* of processing
 * does not leak which failure occurred (use constant-time decryption +
 * full processing of all branches before emitting the error).
 */
enum err edhoc_build_error_message_psk_uniform(uint8_t *out, uint32_t out_max,
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
