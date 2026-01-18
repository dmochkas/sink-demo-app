#include "sink_demo_app/logger_helper.h"

#include <stdio.h>

zlog_category_t* ok_cat = NULL;
zlog_category_t* error_cat = NULL;
zlog_category_t* rx_cat = NULL;

logger_status logger_init(void) {
    const int rc = zlog_init(LOG_CONFIG_FILE);
    if (rc) {
        fprintf(stderr, "Config file %s is corrupt\n", LOG_CONFIG_FILE);
        return LOGGER_INIT_KO;
    }

    ok_cat = zlog_get_category("ok");
    if (!ok_cat) {
        fprintf(stderr, "OK category init failed\n");
        zlog_fini();
        return LOGGER_INIT_KO;
    }

    error_cat = zlog_get_category("error");
    if (!error_cat) {
        fprintf(stderr, "Error category init failed\n");
        zlog_fini();
        return LOGGER_INIT_KO;
    }

    rx_cat = zlog_get_category("rx");
    if (!rx_cat) {
        fprintf(stderr, "RX category init failed\n");
        zlog_fini();
        return LOGGER_INIT_KO;
    }
    zlog_info(rx_cat, "rx logging initialized");

    return LOGGER_INIT_OK;
}
void hex_dump(zlog_category_t* cat,
                     const char* tag,
                     const uint8_t* buf,
                     size_t len)
{
    if (!cat || !tag || !buf) return;

    char line[2048];
    size_t pos = 0;

    pos += snprintf(line + pos, sizeof(line) - pos,
                    "%s (%zu): ", tag, len);

    for (size_t i = 0; i < len && pos + 4 < sizeof(line); i++) {
        pos += snprintf(line + pos, sizeof(line) - pos,
                        "%02x ", buf[i]);
    }

    zlog_info(cat, "%s", line);
}
void log_ahoi_packet(zlog_category_t* cat,
                            const ahoi_packet_t* p)
{
    if (!cat || !p) return;

    zlog_info(cat,
              "AHOI RX: src=%u dst=%u type=%u flags=%u seq=%u pl_size=%u",
              p->src, p->dst, p->type, p->flags, p->seq, p->pl_size);
}
void log_sensor(zlog_category_t* cat,
                       const sensor_data_t* d)
{
    if (!cat || !d) return;

    zlog_info(cat,
              "SENSOR: temp=%.3f pH=%.3f bat=%u",
              d->temp, d->pH, d->bat);
}