#include <vmem/vmem.h>
#include <vmem/vmem_file.h>

#include <param/param.h>
#include "../param_config.h"

#include <crypto/crypto.h>
#include <crypto/crypto_param.h>

VMEM_DEFINE_FILE(crypto, "crypto", "crypto.vmem", 0x100);

void tx_encrypt_cb(param_t * param, int idx) {

    /* Range check */
    if(param_get_uint8(param) > CRYPTO_NUM_KEYS) {
        param_set_uint8(param, 0);
    }
}

PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_KEY1,              crypto_key1,             PARAM_TYPE_DATA,   32, sizeof(uint8_t),  PM_READONLY, crypto_key_generate, NULL, crypto, 0x40, NULL);
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_KEY2,              crypto_key2,             PARAM_TYPE_DATA,   32, sizeof(uint8_t),  PM_READONLY, crypto_key_generate, NULL, crypto, 0x60, NULL);
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_KEY3,              crypto_key3,             PARAM_TYPE_DATA,   32, sizeof(uint8_t),  PM_READONLY, crypto_key_generate, NULL, crypto, 0x80, NULL);
             
PARAM_DEFINE_STATIC_VMEM(PARAMID_TX_ENCRYPT,               tx_encrypt,              PARAM_TYPE_UINT8,  -1, sizeof(uint8_t),  PM_CONF,     tx_encrypt_cb, NULL,   crypto, 0x0A, "Enable encryption using key X.");
PARAM_DEFINE_STATIC_VMEM(PARAMID_RX_ENCRYPT,               rx_decrypt,              PARAM_TYPE_UINT8,  -1, sizeof(uint8_t),  PM_CONF,     NULL, NULL, crypto, 0x0B, "Expect encryption for X reboots.");

PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_NONCE_TX_COUNT,    crypto_nonce_tx_count,   PARAM_TYPE_UINT64,  1, sizeof(uint64_t), PM_TELEM,    NULL, NULL, crypto, 0x28, NULL);
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_NONCE_TX_ID,       crypto_nonce_tx_id,      PARAM_TYPE_UINT8,   1, sizeof(uint8_t),  PM_CONF,     NULL, NULL, crypto, 0x34, NULL);
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_NONCE_RX_COUNT,    crypto_nonce_rx_count,   PARAM_TYPE_UINT64, 10, sizeof(uint64_t), PM_TELEM,    NULL, NULL, crypto, 0xA0, NULL);
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_FAIL_AUTH_COUNT,   crypto_fail_auth_count,  PARAM_TYPE_UINT16,  1, sizeof(uint16_t), PM_ERRCNT,   NULL, NULL, crypto, 0x30, NULL);
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_FAIL_NONCE_COUNT,  crypto_fail_nonce_count, PARAM_TYPE_UINT16,  1, sizeof(uint16_t), PM_ERRCNT,   NULL, NULL, crypto, 0x32, NULL);

void crypto_param_init() {

    vmem_file_init(&vmem_crypto);    
}
