#pragma once

#include <vmem/vmem.h>
#include <param/param.h>

#define PM_CRYPT (1UL << 16)

extern const param_t tx_encrypt;
extern const param_t rx_decrypt;

extern const param_t crypto_key1;
extern const param_t crypto_key2;
extern const param_t crypto_key3;

extern const param_t crypto_nonce_tx_count;
extern const param_t crypto_nonce_tx_id;
extern const param_t crypto_nonce_rx_count;
extern const param_t crypto_fail_auth_count;
extern const param_t crypto_fail_nonce_count;
