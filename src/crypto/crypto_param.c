#include <vmem/vmem.h>

#include <param/param.h>
#include "../param_config.h"

#include "crypto/crypto.h"
#include "crypto/crypto_param.h"

extern vmem_t vmem_crypto;

void tx_encrypt_cb(param_t * param, int idx) {

    /* Range check */
    if(param_get_uint8(param) > CRYPTO_NUM_KEYS) {
        param_set_uint8(param, 0);
    }
}

PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_KEY1,              crypto_key1,             PARAM_TYPE_DATA,   32, sizeof(uint8_t),  PM_READONLY | PM_CRYPT, crypto_key_generate, NULL, crypto, 0x40, "Encryption key 1");
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_KEY2,              crypto_key2,             PARAM_TYPE_DATA,   32, sizeof(uint8_t),  PM_READONLY | PM_CRYPT, crypto_key_generate, NULL, crypto, 0x60, "Encryption key 2");
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_KEY3,              crypto_key3,             PARAM_TYPE_DATA,   32, sizeof(uint8_t),  PM_READONLY | PM_CRYPT, crypto_key_generate, NULL, crypto, 0x80, "Encryption key 3");

PARAM_DEFINE_STATIC_VMEM(PARAMID_TX_ENCRYPT,               tx_encrypt,              PARAM_TYPE_UINT8,  -1, sizeof(uint8_t),  PM_CONF | PM_CRYPT,     tx_encrypt_cb,       NULL, crypto, 0x0A, "Enable encryption using key X (0 disables encryption).");
PARAM_DEFINE_STATIC_VMEM(PARAMID_RX_ENCRYPT,               rx_decrypt,              PARAM_TYPE_UINT8,  -1, sizeof(uint8_t),  PM_CONF | PM_CRYPT,     NULL,                NULL, crypto, 0x0B, "Expect encryption for X reboots.");

PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_NONCE_TX_COUNT,    crypto_nonce_tx_count,   PARAM_TYPE_UINT64,  1, sizeof(uint64_t), PM_TELEM | PM_CRYPT,    NULL,                NULL, crypto, 0x28, "Nonce counter for tx");
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_NONCE_TX_ID,       crypto_nonce_tx_id,      PARAM_TYPE_UINT8,   1, sizeof(uint8_t),  PM_CONF | PM_CRYPT,     NULL,                NULL, crypto, 0x34, "Unique transmitter ID, used only when having more than one independent ground encryption node");
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_NONCE_RX_COUNT,    crypto_nonce_rx_count,   PARAM_TYPE_UINT64, 10, sizeof(uint64_t), PM_TELEM | PM_CRYPT,    NULL,                NULL, crypto,0x800, "Nonce counter for rx");
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_FAIL_AUTH_COUNT,   crypto_fail_auth_count,  PARAM_TYPE_UINT16,  1, sizeof(uint16_t), PM_ERRCNT | PM_CRYPT,   NULL,                NULL, crypto, 0x30, NULL);
PARAM_DEFINE_STATIC_VMEM(PARAMID_CRYPTO_FAIL_NONCE_COUNT,  crypto_fail_nonce_count, PARAM_TYPE_UINT16,  1, sizeof(uint16_t), PM_ERRCNT | PM_CRYPT,   NULL,                NULL, crypto, 0x32, NULL);
