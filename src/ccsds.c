#include <unistd.h>
#include <endian.h>

#include <csp/csp_id.h>

#include <ccsds/ccsds.h>
#include "crypto/crypto_param.h"
#include "crypto/crypto.h"
#include <ccsds/ccsds_randomize.h>

const ccsds_asm_t CCSDS_ASM = 0x1ACFFC1D;

static int min(int a, int b)
{
    if (a < b)
        return a;
    else
        return b;
}

int ccsds_get_num_frames(uint16_t packet_len)
{
    int whole_frames = (packet_len / CCSDS_LEN);
    int remainder = (packet_len % CCSDS_LEN);
    if (remainder)
    {
        return whole_frames + 1;
    }
    else
    {
        return whole_frames;
    }
}

ccsds_frame_obj_t *ccsds_init_frame(ccsds_frame_obj_t *me, bool use_rs, const ccsds_asm_t *ccsds_asm)
{
    if (me) {
        me->idx = 0;
        me->prev_idx = -1;
        me->this_seq = -1;
        me->csp_packet = NULL;
        me->use_rs = use_rs;
        me->ccsds_asm = ccsds_asm;
    }

    return me;
}

int ccsds_pack_next_frame(ccsds_frame_obj_t *me, csp_packet_t *packet, uint8_t *frame, uint8_t seq_num)
{
    int len_total = 0;

    /* If we must, then insert the ASM header into the frame */
    if (me->ccsds_asm) {
        ccsds_asm_t *ccsds_asm = (ccsds_asm_t *)frame;
        (*ccsds_asm) = htobe32(*me->ccsds_asm);
        /* Advance past the ASM header */
        frame += sizeof(ccsds_asm_t);
        len_total += sizeof(ccsds_asm_t);
    }

    /* Always insert the CBLK header information */
    cblk_t *cblk = (cblk_t *)frame;
    cblk->hdr.data_length = htobe16(packet->frame_length);
    cblk->hdr.sequence_number = seq_num;
    cblk->hdr.idx = me->idx;

    /* Copy the CSP packet data from over into the CCSDS frame */
    uint8_t *csp_data = &packet->frame_begin[me->idx * CCSDS_LEN];
    int csp_data_len = min(packet->frame_length - (me->idx * CCSDS_LEN), CCSDS_LEN);
    memcpy(&cblk->data[0], csp_data, csp_data_len);
    len_total += sizeof(cblk_t);

    /* Advance the index */
    me->idx++;

    /* If needed, then do Reed Solomon encoding of the CCSDS frame (excluding the ASM part) */
    if (me->use_rs) {
        reed_solomon_parity_t *parity = (reed_solomon_parity_t *)(frame + sizeof(cblk_t));
        encode_rs_ccsds((uint8_t *)&cblk->hdr, (unsigned char *)parity, 0);
        ccsds_randomize((uint8_t *)&cblk->hdr);
        len_total += sizeof(reed_solomon_parity_t);
    }

    return len_total;
}

void ccsds_unpack_frame(ccsds_frame_obj_t *me, csp_iface_t *iface, uint8_t *frame, time_t ctx_time)
{
    uint8_t dbg_lvl = me->dbg_lvl;

    if (me->ccsds_asm) {
        /* Expect CCSDS ASM */
        ccsds_asm_t *ccsds_asm = (ccsds_asm_t *)frame;
        if (be32toh(*ccsds_asm) != (*me->ccsds_asm))
        {
            if (dbg_lvl > 1) {
                csp_print("WARNING: Non CCSDS frame\n");
            }
            return;
        }
        /* Advance past the ASM marker */
        frame += sizeof(ccsds_asm_t);
    }

    ccsds_frame_naked_t *ccsds_frame = (ccsds_frame_naked_t *)frame;
    if (me->use_rs) {
        int errloc[NROOTS];

        /* Remove the randomize mask from the payload */
        ccsds_randomize((uint8_t *)&ccsds_frame->block);
        /* Now we can Reed Solomon decode the payload */
        memset(errloc,0,sizeof(errloc));
        int derrors = decode_rs_ccsds((uint8_t *)&ccsds_frame->block, &errloc[0], 0, 0);
        if (derrors > 0) {
            if (dbg_lvl > 1) {
                csp_print("WARNING: %d Decode errors was found and fixed at the following locations:\n", derrors);
                for (int i=0; i<derrors;i++) {
                    csp_print("Location: %d\n", errloc[i]);
                }
            }
        }
    }

    uint8_t idx = ccsds_frame->block.hdr.idx;
    uint8_t seq = ccsds_frame->block.hdr.sequence_number;
    uint16_t len = be16toh(ccsds_frame->block.hdr.data_length);

    /* Skip empty (IDLE) frames */
    if ((len == 0) || (len > 2000))
    {
        if (dbg_lvl > 3) {
            csp_print("IDLE: Skipped.\n");
            if (dbg_lvl > 4) {
                csp_hex_dump("CCSDS:", &ccsds_frame->block, 259);
            }
        }
        return;
    }

    if (dbg_lvl > 2) {
        csp_print("FRAME: idx %u, seq %u, len %u\n", idx, seq, len);
        csp_hex_dump("CCSDS:", &ccsds_frame->block, len > 259 ? 259 : len);
    }

    /* Multiple frames in a single CSP packet support */
    uint8_t numframes = ccsds_get_num_frames(len);

    /* Beginning of new CSP packet, reset check variables */
    if (idx == 0)
    {
        me->this_seq = seq;
        me->prev_idx = -1;
    }
    else { 
        /* Check for CCSDS frame loss */
        if (me->this_seq != seq || (me->prev_idx + 1) != idx)
        {
            if (dbg_lvl > 3) {
                csp_print("Discarding packet due to %u != %u || (%u+1) != %u \n", me->this_seq, seq, me->prev_idx, idx);
            }
            csp_buffer_free(me->csp_packet);
            me->csp_packet = NULL;
            return;
        }
    }

    /* We can increment the previously known idx to the current */
    me->prev_idx++;

    /* Allocate CSP packet buffer */
    if (me->csp_packet == NULL)
    {
        if (csp_buffer_remaining() < 10)
        {
            /* Try to throttle the csp_buffer free process */
            usleep(1);
        }
        while ((me->csp_packet = csp_buffer_get(0)) == NULL)
        {
            usleep(1);
        }
        csp_id_setup_rx(me->csp_packet);
        me->csp_packet->timestamp_rx = ctx_time;
    }

    /* Move data into the CSP buffer (with support for spanning multiple frames)*/
    me->csp_packet->frame_length = len;
    memcpy(&me->csp_packet->frame_begin[idx * CCSDS_LEN], &ccsds_frame->block.data[0], min(len - idx * CCSDS_LEN, CCSDS_LEN));

    /* Skip if we expect more data */
    if (numframes > idx + 1)
    {
        if (dbg_lvl > 1) {
            csp_print("Found frame %d of %d with len %d, waiting for next one\n", (idx + 1), numframes, len);
        }
        return;
    }

    if (param_get_uint8(&rx_decrypt))
    {
        me->csp_packet->frame_length = crypto_decrypt(me->csp_packet->frame_begin, me->csp_packet->frame_length);

        if (me->csp_packet->frame_length < 0)
        {
            csp_buffer_free(me->csp_packet);
            me->csp_packet = NULL;
            return;
        }
    }

    /* Parse CSP header */
    if (csp_id_strip(me->csp_packet) < 0)
    {
        csp_buffer_free(me->csp_packet);
        me->csp_packet = NULL;
        return;
    }

    if (dbg_lvl > 3) {
        if (numframes > 0) {
            csp_print("CSP packet stitched together from multiple CCSDS frames, written to the QFIFO (IF:'%s',ADDR:%d, Sz: %d)\n", iface->name, iface->addr, len);
        } else {
            csp_print("CSP packet written to the QFIFO (IF:'%s',ADDR:%d, Sz: %d))\n", iface->name, iface->addr, len);
        }
    }

    /* Send back into CSP, notice calling from task so last argument must be NULL! */
    csp_qfifo_write(me->csp_packet, iface, NULL);
    me->csp_packet = NULL;
}
