#include "cblk/csp_if_cblk.h"

#include <math.h>
#include <stdio.h>
#include <endian.h>
#include <csp/crypto/csp_hmac.h>
#include <csp/csp_id.h>
#include <csp/csp_iflist.h>
#include "crypto/crypto.h"
#include "csp/csp_buffer.h"
#include <param/param.h>

uint8_t _cblk_rx_debug = 0;
uint8_t _cblk_tx_debug = 0;

/* Calculate number of CCSDS frames required to send CSP packet of given size
 * Returns 0 if size exceeds maximum allowed */
static uint8_t num_ccsds_from_csp(uint16_t framesize) {
    if(framesize > (CBLK_DATA_LEN * CBLK_MAX_FRAMES_PER_PACKET)) {
        return 0;
    }
    return (framesize+CBLK_DATA_LEN-1)/CBLK_DATA_LEN;
}

static void forward_other_ifcs(csp_iface_t * iface, csp_packet_t *packet) {

    csp_iface_t * ifc = csp_iflist_get();

    while (ifc != NULL) {

        if (ifc != iface && ifc->addr != 0) {

            csp_packet_t * packet_copy = csp_buffer_clone(packet);

            if (ifc->nexthop(ifc, CSP_NO_VIA_ADDRESS, packet_copy, 1) != CSP_ERR_NONE) {
                csp_buffer_free(packet_copy);
            }
        }
        ifc = ifc->next;
    }
}

int csp_if_cblk_tx(csp_iface_t * iface, uint16_t via, csp_packet_t *packet, int from_me) {

	csp_cblk_interface_data_t * ifdata = iface->interface_data;

    if (_cblk_tx_debug >= 2) {
        csp_hex_dump("packet", packet->data, packet->length);
    }

    if (ifdata->cblk_tx_is_active != NULL && !ifdata->cblk_tx_is_active(iface)) {

        if (from_me) {
            forward_other_ifcs(iface, packet);
        } else {
            iface->drop++;
        }
        csp_buffer_free(packet);
        return CSP_ERR_NONE;
    }

    csp_id_prepend(packet);

    if (_cblk_tx_debug >= 3) {
        csp_hex_dump("tx_frame", packet->frame_begin, packet->frame_length);
    }


    if (param_get_uint8(&tx_encrypt)) {

        if(crypto_encrypt(packet) < 0) {
            csp_buffer_free(packet);
            if (_cblk_tx_debug >= 2) {
                printf("Encryption fail: packet too large to encrypt\n");
            }
            return CSP_ERR_INVAL;
        }

        if (_cblk_tx_debug >= 3) {
            csp_hex_dump("tx_enc", packet->frame_begin, packet->frame_length);
        }
    }

    uint16_t bytes_remain = packet->frame_length;
    uint8_t num_frames = num_ccsds_from_csp(packet->frame_length);

    ifdata->cblk_tx_lock(iface);

    for (int8_t frame_cnt = 0; frame_cnt < num_frames; frame_cnt++) {

        cblk_frame_t * tx_ccsds_buf = ifdata->cblk_tx_buffer_get(iface);
        if (tx_ccsds_buf == NULL) {
            ifdata->cblk_tx_unlock(iface);
            csp_buffer_free(packet);
            return CSP_ERR_NOBUFS;
        }

        memset(tx_ccsds_buf, 0, sizeof(cblk_hdr_t));

        tx_ccsds_buf->hdr.csp_packet_idx = iface->tx;
        tx_ccsds_buf->hdr.ccsds_frame_idx = frame_cnt;
        tx_ccsds_buf->hdr.packet_length = htobe16(packet->frame_length);
        tx_ccsds_buf->hdr.nacl_crypto_key = param_get_uint8(&tx_encrypt);

        if (_cblk_tx_debug >= 1) {
            printf("TX CCSDS header: %u %u %u\n", tx_ccsds_buf->hdr.csp_packet_idx, frame_cnt, packet->frame_length);
        }
        uint16_t segment_len = (CBLK_DATA_LEN < bytes_remain) ? CBLK_DATA_LEN : bytes_remain;

        memcpy(tx_ccsds_buf->data, packet->frame_begin+(packet->frame_length-bytes_remain), segment_len);
        bytes_remain -= segment_len;

        if (ifdata->cblk_tx_send(iface, tx_ccsds_buf) < 0) {
            ifdata->cblk_tx_unlock(iface);
            csp_buffer_free(packet);
            return CSP_ERR_NOBUFS;
        }
    }

    ifdata->cblk_tx_unlock(iface);
    csp_buffer_free(packet);

    return CSP_ERR_NONE;
}

int csp_if_cblk_rx(csp_iface_t * iface, cblk_frame_t *frame, uint32_t len, uint8_t group) {

    csp_cblk_interface_data_t * ifdata = iface->interface_data;

    uint16_t packet_length = be16toh(frame->hdr.packet_length);

    if (_cblk_rx_debug >= 3) {
        printf("RX %p chain %u CCSDS header: %u %u %u\n", frame, group, frame->hdr.csp_packet_idx, frame->hdr.ccsds_frame_idx, packet_length);
    }

    /* minimum header size in CSP version 1*/
    if (packet_length < 4
        /* invalid packet length */
        || (frame->hdr.nacl_crypto_key == 0 && packet_length > CSP_ID2_HEADER_SIZE + CSP_BUFFER_SIZE)
        /* invalid encrypted packet length */
        || (frame->hdr.nacl_crypto_key > 0 && packet_length > CRYPTO_MAC_SIZE + CSP_ID2_HEADER_SIZE + CSP_BUFFER_SIZE)
        /* invalid number of CCSDS frames */
        || frame->hdr.ccsds_frame_idx >= num_ccsds_from_csp(packet_length)) {

        /* This is triggered by dummybursts transmitted when opening channel, in case HW does not filter those */
        return CSP_ERR_NONE;

    } else if (ifdata->rx_packet_idx == frame->hdr.csp_packet_idx && ifdata->rx_frame_idx == frame->hdr.ccsds_frame_idx) { 

        /* We already handled this frame */
        if (_cblk_rx_debug >= 2) printf("Discarding dublicated frame\n");
        return CSP_ERR_NONE;

    } else if (frame->hdr.ccsds_frame_idx == 0) { 

        /* Start handling a new packet */
        ifdata->rx_frame_idx = frame->hdr.ccsds_frame_idx;
        ifdata->rx_packet_idx = frame->hdr.csp_packet_idx;
        /* Setup rx packet moves frame_begin to fit csp header 4 or 6 bytes */
        csp_id_setup_rx(ifdata->rx_packet);
        /* Adjust for crypto MAC if encrypted */
        if (frame->hdr.nacl_crypto_key > 0) {
            ifdata->rx_packet->frame_begin -= CRYPTO_MAC_SIZE;
        }

    } else if (ifdata->rx_frame_idx + 1 != frame->hdr.ccsds_frame_idx || ifdata->rx_packet_idx != frame->hdr.csp_packet_idx) {

        /* We are missing part of the received CSP frame */
        if (_cblk_rx_debug >= 1) {
            printf("Part of CSP frame is missing: Received part %"PRIu8" of %"PRIu8", expected part %"PRIu8" of %"PRIu8"\n", 
                frame->hdr.ccsds_frame_idx, frame->hdr.csp_packet_idx, ifdata->rx_frame_idx+1, ifdata->rx_packet_idx);
        }
        iface->frame++;
        return CSP_ERR_HMAC;

    } else { /* We received the next part of an ongoing CSP frame reception */
        ifdata->rx_frame_idx = frame->hdr.ccsds_frame_idx;
    }

    uint16_t cblk_frame_len = CBLK_DATA_LEN;
    if ((ifdata->rx_frame_idx + 1) * CBLK_DATA_LEN > packet_length) {
        cblk_frame_len = packet_length - ifdata->rx_frame_idx * CBLK_DATA_LEN;
    }

    /* Check for buffer overflow */
    uint8_t * buffer_end = ifdata->rx_packet->data + CSP_BUFFER_SIZE;
    uint8_t * write_end = ifdata->rx_packet->frame_begin + ifdata->rx_packet->frame_length + cblk_frame_len;
    if (write_end > buffer_end) {
        iface->frame++;
        return CSP_ERR_INVAL;
    }

    memcpy(&ifdata->rx_packet->frame_begin[ifdata->rx_packet->frame_length], frame->data, cblk_frame_len);
    ifdata->rx_packet->frame_length += cblk_frame_len;


    if (ifdata->rx_frame_idx + 1 < num_ccsds_from_csp(packet_length)) {
        /* We are still waiting for the last CCSDS frame of the CSP packet */
        return CSP_ERR_NONE;
    }

    if (frame->hdr.nacl_crypto_key > 0) {

        if (_cblk_rx_debug >= 4) {
            csp_hex_dump("-rx_enc", ifdata->rx_packet->frame_begin, packet_length);
        }

        int16_t decrypt_res = crypto_decrypt(ifdata->rx_packet, frame->hdr.nacl_crypto_key);

        if (decrypt_res < 0) {
            iface->autherr++;
            return CSP_ERR_HMAC;
        }

    } else if (param_get_uint8(&rx_decrypt)) {

        iface->autherr++;
        return CSP_ERR_HMAC;

    }

    if (_cblk_rx_debug >= 5) {
        csp_hex_dump("-rx_dec", ifdata->rx_packet->frame_begin, ifdata->rx_packet->frame_length);
    }

    /* Strip and parse CSP header */
    if (csp_id_strip(ifdata->rx_packet) < 0) {
        iface->frame++;
        return CSP_ERR_INVAL;
    }

    if (_cblk_rx_debug >= 4) {
        csp_hex_dump("packet", ifdata->rx_packet->data, ifdata->rx_packet->length);
    }

    csp_qfifo_write(ifdata->rx_packet, iface, NULL);
    ifdata->rx_packet = csp_buffer_get(0);

    return CSP_ERR_NONE;
}

void csp_if_cblk_init(csp_iface_t * iface) {

    csp_cblk_interface_data_t * ifdata = iface->interface_data;

    ifdata->rx_frame_idx = UINT8_MAX;
    ifdata->rx_packet_idx = UINT8_MAX;
    ifdata->rx_packet = csp_buffer_get(0);

    if(ifdata->cblk_tx_lock == NULL || ifdata->cblk_tx_unlock == NULL) {
        printf("csp_if_cblk_init: lock function pointers must be set!\n");
        return;
    }

    iface->nexthop = csp_if_cblk_tx;
}
