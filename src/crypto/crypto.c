#include "crypto/crypto.h"

#include <csp/arch/csp_time.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef USE_TWEETNACL
#include "tweetnacl.h"
#endif

#ifdef USE_SODIUM
#include <sodium.h>
#endif

#include "crypto/crypto_param.h"
#define CSP_ID2_HEADER_SIZE 6

#define NONCE_SIZE (sizeof(uint64_t) + sizeof(uint8_t))

_Static_assert(CSP_PACKET_PADDING_BYTES > crypto_secretbox_ZEROBYTES + CSP_ID2_HEADER_SIZE, "Not enough padding before csp packet for in-place encryption!");

uint8_t _crypto_beforenm[CRYPTO_NUM_KEYS][crypto_secretbox_KEYBYTES];

void crypto_key_generate(param_t * param, int idx) {

    param_get_data(&crypto_key1, _crypto_beforenm[0], sizeof(_crypto_beforenm[0]));
    param_get_data(&crypto_key2, _crypto_beforenm[1], sizeof(_crypto_beforenm[1]));
    param_get_data(&crypto_key3, _crypto_beforenm[2], sizeof(_crypto_beforenm[2]));
}

/*
There is a 32-octet padding requirement on the plaintext buffer that you pass to crypto_box.
Internally, the NaCl implementation uses this space to avoid having to allocate memory or
use static memory that might involve a cache hit (see Bernstein's paper on cache timing
side-channel attacks for the juicy details).

Similarly, the crypto_box_open call requires 16 octets of zero padding before the start
of the actual ciphertext. This is used in a similar fashion. These padding octets are not
part of either the plaintext or the ciphertext, so if you are sending ciphertext across the
network, don't forget to remove them!
*/
uint8_t decrypt_out[CSP_PACKET_PADDING_BYTES+CSP_BUFFER_SIZE+crypto_secretbox_ZEROBYTES];
int16_t crypto_decrypt(uint8_t * msg_out, uint8_t * decrypt_in, uint16_t ciphertext_len, uint8_t crypto_key) {

    ciphertext_len = ciphertext_len - NONCE_SIZE;

    /* Receive nonce */
    uint8_t decrypt_nonce[crypto_box_NONCEBYTES] = {};
    memcpy(&decrypt_nonce, &decrypt_in[crypto_secretbox_BOXZEROBYTES+ciphertext_len], NONCE_SIZE);

    /* Make room for zerofill at the beginning of message */
    memset(decrypt_in, 0, crypto_secretbox_BOXZEROBYTES);

    /* Make room for zerofill at the beginning of message */
    memset(decrypt_out, 0, crypto_secretbox_ZEROBYTES);

    /* Decryption */
    if(crypto_box_open_afternm(decrypt_out, decrypt_in, ciphertext_len, decrypt_nonce, _crypto_beforenm[crypto_key-1]) != 0) {
        param_set_uint16(&crypto_fail_auth_count, param_get_uint16(&crypto_fail_auth_count) + 1);
        return -1;
    }

    /* Message successfully decrypted, check for valid nonce */
    uint64_t nonce_counter;
    memcpy(&nonce_counter, decrypt_nonce, sizeof(uint64_t));
    uint8_t nounce_group = decrypt_nonce[sizeof(uint64_t)];
    uint64_t nonce_rx = param_get_uint64_array(&crypto_nonce_rx_count, nounce_group);
    if(nonce_counter <= nonce_rx) {
        param_set_uint16(&crypto_fail_nonce_count, param_get_uint16(&crypto_fail_nonce_count) + 1);
        return -1;
    }

    /* Copy encrypted data back to msgbuffer */
    memcpy(msg_out, &decrypt_out[crypto_secretbox_ZEROBYTES], ciphertext_len - crypto_secretbox_KEYBYTES);

    /* Update counter with received value so that next sent value is higher */
    param_set_uint64_array(&crypto_nonce_rx_count, nounce_group, nonce_counter);

    /* Return useable length */
    return ciphertext_len - crypto_secretbox_KEYBYTES;
}

uint8_t encrypt_in[crypto_secretbox_ZEROBYTES+CSP_PACKET_PADDING_BYTES+CSP_BUFFER_SIZE];
int16_t crypto_encrypt(uint8_t * msg_out, uint8_t * msg_in, uint16_t msg_len) {

    uint64_t tx_nonce = param_get_uint64(&crypto_nonce_tx_count) + 1;
    param_set_uint64(&crypto_nonce_tx_count, tx_nonce);

    /* Pack nonce into 24-bytes format, expected by NaCl */
    unsigned char nonce[crypto_box_NONCEBYTES] = {};
    memcpy(nonce, &tx_nonce, sizeof(uint64_t));
    nonce[sizeof(uint64_t)] = param_get_uint8(&crypto_nonce_tx_id);

    /* Copy msg to new buffer, to make room for zerofill */
    memcpy(&encrypt_in[crypto_secretbox_ZEROBYTES], msg_in, msg_len);

    /* Make room for zerofill at the beginning of message */
    memset(encrypt_in, 0, crypto_secretbox_ZEROBYTES);

    /* Make room for zerofill at the beginning of message */
    memset(msg_out, 0, crypto_secretbox_BOXZEROBYTES);

    if (crypto_box_afternm(msg_out, encrypt_in, crypto_secretbox_KEYBYTES + msg_len, nonce, _crypto_beforenm[param_get_uint8(&tx_encrypt)-1]) != 0) {
        return -1;
    }

    /* Add nonce at the end of the packet */
    memcpy(&msg_out[crypto_secretbox_BOXZEROBYTES + msg_len + crypto_secretbox_KEYBYTES], nonce, NONCE_SIZE);

    return msg_len + crypto_secretbox_KEYBYTES + NONCE_SIZE;
}

/**
 * @brief Encrypts a CSP packet payload in-place using NaCl/libsodium.
 *
 * This function performs authenticated encryption on the data contained in the
 * packet structure. It modifies the packet's data buffer directly, adjusting
 * the `frame_begin` pointer and `frame_length` to account for the prepended
 * Message Authentication Code (MAC) and the appended Nonce.
 *
 * **Memory Layout Transformation:**
 *
 * **Before:**
 * @code
 * [  Headroom  ] [ Payload (N) ] [      Tailroom      ]
 * ^
 * frame_begin
 * @endcode
 *
 * **After:**
 * @code
 * [ MAC (16) ] [ Encrypted Payload (N) ] [ 0x00 (16) ] [ Nonce (8) ] [ TX ID (1) ]
 * ^
 * frame_begin
 * @endcode
 *
 * @pre **Compile-time Check:** `CSP_PACKET_PADDING_BYTES` must be greater than
 * `crypto_secretbox_ZEROBYTES + CSP_ID2_HEADER_SIZE`. This is enforced by a
 * `_Static_assert` to ensure safe headless padding.
 *
 * @param[in,out] packet Pointer to the CSP packet structure. The `frame_begin`,
 * `frame_length`, and buffer contents will be modified.
 *
 * @return
 * - \b CSP_ERR_NONE: Encryption successful.
 * - \b CSP_ERR_INVAL: Packet buffer too small for prepending nonce and zerofill.
 */
int16_t crypto_encrypt_inplace(csp_packet_t * packet) {

    /* Check that there is enough space to postpend nonce and 16 byte zerofill */
    if(packet->length + NONCE_SIZE + crypto_secretbox_BOXZEROBYTES > CSP_BUFFER_SIZE) {
        return CSP_ERR_INVAL;
    }

    /* Update and get transmit nonce */
    uint64_t tx_nonce = param_get_uint64(&crypto_nonce_tx_count) + 1;
    param_set_uint64(&crypto_nonce_tx_count, tx_nonce);

    /* Pack nonce into 24-bytes format, expected by NaCl */
    unsigned char nonce[crypto_box_NONCEBYTES] = {};
    memcpy(nonce, &tx_nonce, sizeof(uint64_t));
    /* Add nonce ID to nonce */
    nonce[sizeof(uint64_t)] = param_get_uint8(&crypto_nonce_tx_id);

    /* Make room for zerofill at the beginning of message */
    uint8_t * padding_begin = packet->frame_begin - crypto_secretbox_ZEROBYTES;
    memset(padding_begin, 0, crypto_secretbox_ZEROBYTES);

    /* Encryption only returns -1 if mlen < 32 */
    crypto_box_afternm(padding_begin, padding_begin, packet->frame_length + crypto_secretbox_ZEROBYTES, nonce, _crypto_beforenm[param_get_uint8(&tx_encrypt)-1]);

    /* Adjust packet pointers and length for the prepended MAC */
    packet->frame_begin -= crypto_secretbox_MACBYTES;
    packet->frame_length += crypto_secretbox_MACBYTES;

    /* Zero out the 16 bytes between the end of the encrypted data and the nonce for backwards compatibility */
    memset(packet->frame_begin + packet->frame_length, 0, crypto_secretbox_BOXZEROBYTES);

    /* Add nonce at the end of the packet plus 16 bytes for backwards compatibility */
    memcpy(packet->frame_begin + (crypto_secretbox_BOXZEROBYTES + packet->frame_length), nonce, NONCE_SIZE);
    packet->frame_length += NONCE_SIZE + crypto_secretbox_BOXZEROBYTES;

    return CSP_ERR_NONE;
}

void crypto_init() {

    crypto_key_generate(NULL, -1);

    if (param_get_uint8(&rx_decrypt) > 0) {
        param_set_uint8(&rx_decrypt, param_get_uint8(&rx_decrypt) - 1);
    }
}
