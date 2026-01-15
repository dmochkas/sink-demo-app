#pragma once

#include <stdint.h>
#include <stddef.h>

typedef enum {
    L2_INIT_OK, L2_INIT_ERROR
} l2_init_status;

typedef enum {
    L2_RECV_OK,
    L2_RECV_TIMEOUT,
    L2_RECV_KO
} l2_recv_status;

l2_init_status l2_init(void);

void l2_set_id(uint32_t id);

uint32_t* l2_get_id(void);

uint8_t* l2_get_id_byte(void);

void l2_recv_prepare(const void* params);

l2_recv_status l2_recv_run(uint8_t* payload, size_t cap, size_t* out_len);

#ifdef L2_AHOI_EXT
#include "ext/l2_ahoi_ext.h"
#endif
