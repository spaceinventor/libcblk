#pragma once

#include <csp/csp.h>

#include <param/param.h>

#define CRYPTO_NUM_KEYS 3
#define CSP_ID2_HEADER_SIZE 6

extern param_t tx_encrypt;
extern param_t rx_decrypt;

void crypto_key_generate(param_t * param, int idx);
int16_t crypto_decrypt(csp_packet_t * packet, uint8_t crypto_key);
int16_t crypto_encrypt(csp_packet_t * packet);
void crypto_init();
