// =============================================================================
// EDHOC Hardware Accelerator — Firmware Example
// Full Initiator + Responder loopback (single-threaded, same SoC)
//
// Matches: chipyard.crypto.edhoc wrapper & EDHOCCtrlRegs register map
// =============================================================================

#include <stdio.h>
#include <string.h>
#include "edhoc_hw.h"

// We'll re-use one instance for both roles to keep things simple.
// In a real dual-core system, Initiator & Responder would be on different
// addresses or on two separate EDHOC cores.
//
// This example just shows the register-level sequence for the INITIATOR.
// A real system uses interrupts or DMA instead of blocking polls.

#define TIMEOUT 10000000

// ---- Example Pre-Shared Key (replace with real credentials) ----
static const uint32_t eph_key[8] = {  // 256-bit ephemeral secret key
    0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
    0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20
};

// ---- Helpers ---------------------------------------------------------------

static void print_hex(const char *label, const uint8_t *buf, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

// ---- Initiator Flow --------------------------------------------------------
//
// Step  FSM waits for
// ----  ---------------------------------------------------------------
// 1     Write params + eph key, start as initiator
// 2     Wait output_valid → read MSG1, send output_ack
// 3     Wait msg_ready → write MSG2, pulse msg_valid
// 4     Wait output_valid → read MSG3, send output_ack
// 5     Wait msg_ready → write MSG4, pulse msg_valid
// 6     Wait done → OSCORE keys available
// -----------------------------------------------------------------------

int edhoc_initiator_run(void) {
    uint8_t msg1[37], msg2[37], msg3[37], msg4[37];
    int rc;

    printf("[INIT] === Starting EDHOC Initiator ===\n");

    // ----- 0. Reset & configure -----
    edhoc_sw_reset();
    edhoc_clear_flags();

    // Ephemeral key
    edhoc_set_ephemeral_key(eph_key);

    // Parameters: c_x=0x00, method=0 (PSK), suite=7, id_cred_psk=0x0A
    edhoc_set_params(0x00, 0x00, 0x07, 0x0A);

    // KIDs
    edhoc_set_kids(0x01, 0x02);

    // IDs (example, 8 bytes each)
    edhoc_set_id_initiator(0x0102030405060708ULL);
    edhoc_set_id_responder(0x090A0B0C0D0E0F10ULL);

    // Bypass XDRBG for deterministic testing
    // (set second arg to 0 for production with real TRNG/XDRBG)
    edhoc_start_initiator(/*bypass=*/1);

    // ----- 1. Get MSG1 -----
    printf("[INIT] Waiting for MSG1 (output_valid)...\n");
    rc = edhoc_wait_output_valid(TIMEOUT);
    if (rc) { printf("[INIT] ERROR waiting MSG1 (%d)\n", rc); return rc; }

    edhoc_capture_output(msg1, 37);
    print_hex("[INIT] MSG1", msg1, 37);

    // >>> In a real system: send msg1 to responder over CoAP/serial <<<

    // ----- 2. Feed MSG2 from responder -----
    printf("[INIT] Waiting for msg_ready (to accept MSG2)...\n");
    rc = edhoc_wait_msg_ready(TIMEOUT);
    if (rc) { printf("[INIT] ERROR waiting msg_ready (%d)\n", rc); return rc; }
    edhoc_clear_flags();  // clear sticky msg_ready before feeding

    // >>> In a real system: receive msg2 from responder <<<
    // For now use dummy data (replace with actual responder output)
    memset(msg2, 0xAA, 37);

    edhoc_feed_message(msg2, 37);

    // ----- 3. Get MSG3 -----
    printf("[INIT] Waiting for MSG3 (output_valid)...\n");
    rc = edhoc_wait_output_valid(TIMEOUT);
    if (rc) { printf("[INIT] ERROR waiting MSG3 (%d)\n", rc); return rc; }

    edhoc_capture_output(msg3, 37);
    print_hex("[INIT] MSG3", msg3, 37);

    // >>> send msg3 to responder <<<

    // ----- 4. Feed MSG4 from responder -----
    printf("[INIT] Waiting for msg_ready (to accept MSG4)...\n");
    rc = edhoc_wait_msg_ready(TIMEOUT);
    if (rc) { printf("[INIT] ERROR waiting msg_ready (%d)\n", rc); return rc; }
    edhoc_clear_flags();

    // >>> receive msg4 from responder <<<
    memset(msg4, 0xBB, 37);

    edhoc_feed_message(msg4, 37);

    // ----- 5. Wait for completion -----
    printf("[INIT] Waiting for done...\n");
    rc = edhoc_wait_done(TIMEOUT);
    if (rc) { printf("[INIT] ERROR waiting done (%d)\n", rc); return rc; }

    printf("[INIT] === EDHOC Complete ===\n");
    printf("[INIT] Status = 0x%08x\n", edhoc_status());

    if (edhoc_oscore_keys_valid()) {
        printf("[INIT] OSCORE keys are available!\n");
    }
    return 0;
}

// ---- External AEAD Example -------------------------------------------------
int edhoc_aead_encrypt_example(void) {
    printf("[AEAD] === External AEAD Encrypt ===\n");

    edhoc_clear_flags();

    // Write AAD
    edhoc_write(EDHOC_AEAD_AAD(0), 0x11223344);
    edhoc_write(EDHOC_AEAD_AAD(1), 0x55667788);
    edhoc_write(EDHOC_AEAD_AAD(2), 0x00000000);
    edhoc_write(EDHOC_AEAD_AAD(3), 0x00000000);

    // Write plaintext
    edhoc_write(EDHOC_AEAD_DIN(0), 0xDEADBEEF);
    edhoc_write(EDHOC_AEAD_DIN(1), 0xCAFEBABE);
    edhoc_write(EDHOC_AEAD_DIN(2), 0x00000000);
    edhoc_write(EDHOC_AEAD_DIN(3), 0x00000000);

    // Lengths: aad_len=8 bytes, data_len=8 bytes
    edhoc_write(EDHOC_AEAD_LENGTHS, (8 << 0) | (8 << 4));

    // Nonce components
    edhoc_write(EDHOC_AEAD_SENDER_ID, 0x01);
    edhoc_write(EDHOC_AEAD_PIV(0), 0x00000001);
    edhoc_write(EDHOC_AEAD_PIV(1), 0x00);

    // Start encrypt (control: aead_start=1, aead_encrypt=1, use_sender_key=1)
    uint32_t ctrl = CTRL_AEAD_START | CTRL_AEAD_ENCRYPT | CTRL_AEAD_USE_SENDER;
    edhoc_write(EDHOC_CONTROL, ctrl);

    // Wait for completion
    int rc = edhoc_wait_aead_done(TIMEOUT);
    if (rc) { printf("[AEAD] ERROR (%d)\n", rc); return rc; }

    // Read ciphertext
    printf("[AEAD] Ciphertext: ");
    for (int i = 0; i < 4; i++)
        printf("%08x ", edhoc_read(EDHOC_AEAD_DOUT(i)));
    printf("\n");

    // Read tag
    printf("[AEAD] Tag:        ");
    for (int i = 0; i < 4; i++)
        printf("%08x ", edhoc_read(EDHOC_AEAD_TAG(i)));
    printf("\n");

    return 0;
}

// ---- Main ------------------------------------------------------------------
int main(void) {
    printf("EDHOC HW Accelerator Test\n");
    printf("Base address: 0x%lx\n\n", (unsigned long)EDHOC_BASE);

    int rc = edhoc_initiator_run();
    if (rc == 0) {
        printf("\n");
        rc = edhoc_aead_encrypt_example();
    }
    return rc;
}
