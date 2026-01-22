#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
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

/* Generic dump + packet log */
void hex_dump(zlog_category_t* cat, const char* prefix, const uint8_t* buf, size_t len);
void log_ahoi_packet(zlog_category_t* cat, const ahoi_packet_t* p);
void log_sensor(zlog_category_t* cat, const sensor_data_t* d);

/* Parse + normalize helpers (receiver-side) */
int log_parsed_ipv6_udp_coap(const uint8_t *pkt, size_t pkt_len);
/* Build canonical packet (TX-like): inserts 0xFF marker, fixes lengths and UDP checksum */
int normalize_ipv6_udp_coap_packet(const uint8_t *decomp, size_t decomp_len,
                                   uint8_t *out, size_t out_cap, size_t *out_len);
