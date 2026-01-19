#pragma once
#include <stdint.h>
#include <zlog.h>
#include <ahoilib.h>
#include <sink_demo_app/services/sensor_service.h>

typedef enum {
    LOGGER_INIT_OK, LOGGER_INIT_KO
} logger_status;

extern zlog_category_t* ok_cat;
extern zlog_category_t* error_cat;
extern zlog_category_t* rx_cat;

logger_status logger_init(void);
void hex_dump(zlog_category_t* cat, const char* prefix, const uint8_t* buf, size_t len);
void log_ahoi_packet(zlog_category_t* cat, const ahoi_packet_t* p);
void log_sensor(zlog_category_t* cat, const sensor_data_t* d);