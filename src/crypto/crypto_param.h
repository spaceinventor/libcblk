#pragma once

#include <vmem/vmem.h>
#include <param/param.h>

extern vmem_t vmem_crypto;

extern param_t tx_encrypt;
extern param_t rx_decrypt;

extern param_t crypto_key1;
extern param_t crypto_key2;
extern param_t crypto_key3;

extern param_t crypto_nonce_tx_count;
extern param_t crypto_nonce_tx_id;
extern param_t crypto_nonce_rx_count;
extern param_t crypto_fail_auth_count;
extern param_t crypto_fail_nonce_count;

void crypto_param_init();