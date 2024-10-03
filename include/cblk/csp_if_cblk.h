#pragma once

#include <stdint.h>

#include <csp/csp.h>
#include <param/param.h>

typedef enum { CBLK_EXTHDR_NOSUPPORT = 0b00, CBLK_EXTHDR_SUPPORT = 0b01, CBLK_EXTHDR_PRESENT = 0b10} ext_hdr_e;

typedef struct __attribute__((packed))
{
    /* Byte 0 */
    uint8_t                 ccsds_frame_idx : 4; //! CCSDS frame counter for current packet
    uint8_t                 aes             : 1; //! 0 = NaCL if crypto_key is set, 1 = AES (not currently supported)
    uint8_t                 nacl_crypto_key : 2; //! 0 = no encryption, 1-3 NaCL pre-shared key encryption
    uint8_t                 nacl_reserved   : 1;
    /* Byte 1 */
    uint8_t                 csp_packet_idx  : 5; //! CSP packet counter
    ext_hdr_e               ext_hdr         : 2; //! Indicate support and inclusion of extended header (not currently supported)
    uint8_t                 reserved1       : 1;

    /* Byte 2 & 3*/
    uint16_t                data_length     :16; //! Data length in RS frame in bytes

} cblk_hdr_t;

typedef struct __attribute__((packed))
{
    cblk_hdr_t              hdr;                 //! Space Inventor specific header
    uint8_t                 data[];              //! Space Inventor specific data
} cblk_frame_t;

#define CCSDS_FRAME_LEN 223
#define CBLK_DATA_LEN (CCSDS_FRAME_LEN-sizeof(cblk_hdr_t))

typedef struct {

    /* Implement this function in case CSP packets shall be re-routed when RF interface is inactive */
    int (*cblk_tx_is_active)(csp_iface_t * iface);

    /* Function provided by implementation to provide a buffer for transmitting a CCSDS frame*/
    cblk_frame_t* (*cblk_tx_buffer_get)(csp_iface_t* iface);

    /* Function provided by implementation to send a CCSDS frame */
    int (*cblk_tx_send)(csp_iface_t* iface, cblk_frame_t* frame);

    /* Variables for internal use */
    uint8_t rx_packet_idx;
    uint8_t rx_frame_idx;
    csp_packet_t *rx_packet;

} csp_cblk_interface_data_t;

/* This function must be called when a new CCSDS frame is received */
int csp_if_cblk_rx(csp_iface_t * iface, cblk_frame_t *frame, uint32_t len, uint8_t group);

/* Function must be called before registering the interface in CSP */
void csp_if_cblk_init(csp_iface_t * iface);

/* Variables to set to enable printing debug information to stdout */
extern uint8_t _cblk_rx_debug;
extern uint8_t _cblk_tx_debug;
