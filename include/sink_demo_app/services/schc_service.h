#pragma once
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SCHC_OK = 0,
    SCHC_ERR = 1,
    SCHC_BUF_TOO_SMALL = 2,
    SCHC_MODE_NOT_AVAILABLE = 3
} schc_status_t;

schc_status_t schc_service_init(void);

schc_status_t schc_service_decompress(const uint8_t* in, size_t in_len,
                                      uint8_t* out, size_t out_cap,
                                      size_t* out_len);
