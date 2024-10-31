#include "cblk/csp_if_cblk.h"

#include <stdio.h>
#include <endian.h>
#include <csp/crypto/csp_hmac.h>
#include <csp/csp_id.h>
#include <csp/csp_iflist.h>
#include "crypto/crypto.h"
#include <param/param.h>

uint8_t _cblk_rx_debug = 0;
uint8_t _cblk_tx_debug = 0;

static uint8_t num_ccsds_from_csp(uint16_t framesize) {

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

    uint16_t frame_length = packet->frame_length;
    uint8_t* frame_begin = packet->frame_begin;

    if (param_get_uint8(&tx_encrypt)) {
        frame_length = crypto_encrypt(ifdata->packet_enc, packet->frame_begin, packet->frame_length);
        frame_begin = &ifdata->packet_enc[CRYPTO_PREAMP];

        if (_cblk_tx_debug >= 3) {
            csp_hex_dump("tx_enc", frame_begin, frame_length);
        }
    }

    uint16_t bytes_remain = frame_length;
    for (int8_t frame_cnt = 0; frame_cnt < num_ccsds_from_csp(frame_length); frame_cnt++) {

        cblk_frame_t * tx_ccsds_buf = ifdata->cblk_tx_buffer_get(iface);
        if (tx_ccsds_buf == NULL) {
            csp_buffer_free(packet);
            return CSP_ERR_NOBUFS;
        }

        memset(tx_ccsds_buf, 0, sizeof(cblk_hdr_t));

        tx_ccsds_buf->hdr.csp_packet_idx = iface->tx;
        tx_ccsds_buf->hdr.ccsds_frame_idx = frame_cnt;
        tx_ccsds_buf->hdr.data_length = htobe16(frame_length);
        tx_ccsds_buf->hdr.nacl_crypto_key = param_get_uint8(&tx_encrypt);

        if (_cblk_tx_debug >= 1) {
            printf("TX CCSDS header: %u %u %u\n", tx_ccsds_buf->hdr.csp_packet_idx, frame_cnt, frame_length);
        }
        uint16_t segment_len = (CBLK_DATA_LEN < bytes_remain) ? CBLK_DATA_LEN : bytes_remain;

        memcpy(tx_ccsds_buf->data, frame_begin+(frame_length-bytes_remain), segment_len);
        bytes_remain -= segment_len;

        if (ifdata->cblk_tx_send(iface, tx_ccsds_buf) < 0) {
            csp_buffer_free(packet);
            return CSP_ERR_NOBUFS;
        }
    }

    csp_buffer_free(packet);

    return CSP_ERR_NONE;
}

int csp_if_cblk_rx(csp_iface_t * iface, cblk_frame_t *frame, uint32_t len, uint8_t group) {

	csp_cblk_interface_data_t * ifdata = iface->interface_data;

    uint16_t frame_length = be16toh(frame->hdr.data_length);

    if (_cblk_rx_debug >= 1) {
        printf("RX %p chain %u CCSDS header: %u %u %u\n", frame, group, frame->hdr.csp_packet_idx, frame->hdr.ccsds_frame_idx, frame_length);
    }

    if (frame_length < 4 || (frame->hdr.nacl_crypto_key == 0 && frame_length > CSP_PACKET_PADDING_BYTES + CSP_BUFFER_SIZE)
        || (frame->hdr.nacl_crypto_key > 0 && frame_length > CSP_PACKET_PADDING_BYTES + CSP_BUFFER_SIZE + CRYPTO_POSTAMP)
        || frame->hdr.ccsds_frame_idx >= num_ccsds_from_csp(frame_length)) {

        /* This is triggered by dummybursts transmitted when opening channel, in case HW does not filter those */
        return CSP_ERR_NONE;

    } else if (ifdata->rx_packet_idx == frame->hdr.csp_packet_idx && ifdata->rx_frame_idx == frame->hdr.ccsds_frame_idx) { 

        /* We already handled this frame */
        if (_cblk_rx_debug >= 1) printf("Discarding dublicated frame\n");
        return CSP_ERR_NONE;

    } else if (frame->hdr.ccsds_frame_idx == 0) { 

        /* Start handling a new packet */
        ifdata->rx_frame_idx = frame->hdr.ccsds_frame_idx;
        ifdata->rx_packet_idx = frame->hdr.csp_packet_idx;

    } else if (ifdata->rx_frame_idx+1 != frame->hdr.ccsds_frame_idx || ifdata->rx_packet_idx != frame->hdr.csp_packet_idx) {

        /* We are missing part of the received CSP frame */
        if (_cblk_rx_debug >= 1) {
            printf("Part of CSP frame is missing: Received part %d of %d, expected part %d of %d\n", 
                frame->hdr.ccsds_frame_idx, frame->hdr.csp_packet_idx, ifdata->rx_frame_idx+1, ifdata->rx_packet_idx);
        }
        iface->frame++;
        return CSP_ERR_HMAC;

    } else { /* We received the next part of an ongoing CSP frame reception */
        ifdata->rx_frame_idx = frame->hdr.ccsds_frame_idx;
    }

    uint16_t cblk_frame_len = CBLK_DATA_LEN;
    if ((ifdata->rx_frame_idx+1)*CBLK_DATA_LEN > frame_length) {
        cblk_frame_len = frame_length - ifdata->rx_frame_idx*CBLK_DATA_LEN;
    }

    memcpy(&ifdata->packet_dec[CRYPTO_PREAMP+ifdata->rx_frame_idx*CBLK_DATA_LEN], frame->data, cblk_frame_len);

    if (ifdata->rx_frame_idx+1 < num_ccsds_from_csp(frame_length)) {
        /* We are still waiting for the last CCSDS frame of the CSP packet */
        return CSP_ERR_NONE;
    }

    csp_packet_t* rx_packet = csp_buffer_get(frame_length);
    csp_id_setup_rx(rx_packet);

    if (frame->hdr.nacl_crypto_key > 0) {

        if (_cblk_rx_debug >= 3) {
            csp_hex_dump("-rx_enc", &ifdata->packet_dec[CRYPTO_PREAMP], frame_length);
        }

        int16_t dec_frame_length = crypto_decrypt(rx_packet->frame_begin, ifdata->packet_dec, frame_length, frame->hdr.nacl_crypto_key);

        if (dec_frame_length < 0) {
            iface->autherr++;
            csp_buffer_free(rx_packet);
            return CSP_ERR_HMAC;
        }

        rx_packet->frame_length = dec_frame_length;

    } else if (param_get_uint8(&rx_decrypt)) {

        iface->autherr++;
        csp_buffer_free(rx_packet);
        return CSP_ERR_HMAC;

    } else {

        memcpy(rx_packet->frame_begin, &ifdata->packet_dec[CRYPTO_PREAMP], frame_length);
        rx_packet->frame_length = frame_length;
    }

    if (_cblk_rx_debug >= 3) {
        csp_hex_dump("-rx_dec", rx_packet->frame_begin, rx_packet->frame_length);
    }

    /* Strip and parse CSP header */
    if (csp_id_strip(rx_packet) < 0) {
        iface->frame++;
        csp_buffer_free(rx_packet);
        return CSP_ERR_INVAL;
    }

    if (_cblk_rx_debug >= 2) {
        csp_hex_dump("packet", rx_packet->data, rx_packet->length);
    }

    csp_qfifo_write(rx_packet, iface, NULL);

    return CSP_ERR_NONE;
}

void csp_if_cblk_init(csp_iface_t * iface) {

	csp_cblk_interface_data_t * ifdata = iface->interface_data;

    ifdata->rx_frame_idx = -1;
    ifdata->rx_packet_idx = -1;

    iface->nexthop = csp_if_cblk_tx;
}
