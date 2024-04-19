#pragma once

#include <inttypes.h>
#include <time.h>

#include <csp/csp.h>

#include "rs/rs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CCSDS_LEN 219

typedef uint32_t ccsds_asm_t;

typedef struct __attribute__((packed))
{
    uint8_t                 idx;                //! Space Inventor index
    uint8_t                 sequence_number;    //! Space Inventor Radio Sequence number
    uint16_t                data_length;        //! Data length in RS frame in bytes
} cblk_hdr_t;

#define CHUNK_SIZE (RS_BLOCK_LENGTH - sizeof(cblk_hdr_t) - RS_CHECK_LENGTH)

typedef struct __attribute__((packed))
{
    cblk_hdr_t              hdr;                //! Space Inventor specific header
    uint8_t                 data[CHUNK_SIZE];   //! Space Inventor specific data
} cblk_t;

typedef uint8_t reed_solomon_parity_t[RS_CHECK_LENGTH];   //! CCSDS Reed Solomon parity

typedef struct __attribute__((packed))
{
    ccsds_asm_t             ccsds_asm;          //! CCSDS ASM is 0x1ACFFC1D
    cblk_t                  block;              //! CBLK
    reed_solomon_parity_t   parity;             //! CCSDS Reed Solomon parity
} ccsds_frame_t;

typedef struct __attribute__((packed))
{
    cblk_t                  block;              //! CBLK
    reed_solomon_parity_t   parity;             //! CCSDS Reed Solomon parity
} ccsds_frame_naked_t;

typedef struct {
    uint32_t                ccsds_asm;          //! CCSDS ASM is 0x1ACFFC1D
    uint8_t                 idx;                //! Space Inventor index
    uint8_t                 sequence_number;    //! Space Inventor Radio Sequence number
    uint16_t                data_length;        //! Data length in RS frame in bytes
    uint8_t                 csp_packet[];
} frame_header_t;

typedef struct {
    uint8_t                 idx;
    uint8_t                 prev_idx;
    uint8_t                 this_seq;
    csp_packet_t           *csp_packet;
    bool                    use_rs;
    const ccsds_asm_t      *ccsds_asm;
} ccsds_frame_obj_t;

extern const ccsds_asm_t CCSDS_ASM;

extern ccsds_frame_obj_t *ccsds_init_frame(ccsds_frame_obj_t *me, bool use_rs, const ccsds_asm_t *ccsds_asm);
extern int ccsds_get_num_frames(uint16_t packet_len);
extern void ccsds_unpack_frame(ccsds_frame_obj_t *me, csp_iface_t *iface, uint8_t *frame, time_t ctx_time);
extern int ccsds_pack_next_frame(ccsds_frame_obj_t *me, csp_packet_t *packet, uint8_t *frame, uint8_t seq_num);

#ifdef __cplusplus
}
#endif