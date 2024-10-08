#pragma once

#include <csp/csp.h>

#include <param/param.h>

#define CRYPTO_NUM_KEYS 3

extern param_t tx_encrypt;
extern param_t rx_decrypt;

void crypto_key_generate(param_t * param, int idx);
int16_t crypto_decrypt(uint8_t * msg_out, uint8_t * ciphertext_in, uint16_t ciphertext_len, uint8_t crypto_key);
int16_t crypto_encrypt(uint8_t * msg_out, uint8_t * msg_in, uint16_t msg_len);
void crypto_init();
