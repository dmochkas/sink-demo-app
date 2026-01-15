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
