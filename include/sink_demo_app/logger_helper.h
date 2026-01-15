#pragma once

#include <zlog.h>

typedef enum {
    LOGGER_INIT_OK, LOGGER_INIT_KO
} logger_status;

extern zlog_category_t* ok_cat;
extern zlog_category_t* error_cat;
extern zlog_category_t* rx_cat;

logger_status logger_init(void);
