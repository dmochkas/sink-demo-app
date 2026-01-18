#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <ahoi_serial/ahoi_defs.h>
#include <ahoilib.h>


#include "sink_demo_app/logger_helper.h"
#include "sink_demo_app/cli_helper.h"
#include "sink_demo_app/services/schc_service.h"
#include "sink_demo_app/services/sensor_service.h"

#ifndef RX_TIMEOUT_MS
#define RX_TIMEOUT_MS 1500
#endif



static void handle_schc_and_log(const uint8_t* schc_in, size_t schc_in_len)
{
    if (!schc_in || schc_in_len == 0) {
        zlog_warn(rx_cat, "Empty SCHC input");
        return;
    }

    hex_dump(rx_cat, "SCHC IN", schc_in, schc_in_len);

    uint8_t out[512];
    size_t out_len = 0;

    const schc_status_t ds = schc_service_decompress(
        schc_in, schc_in_len,
        out, sizeof(out),
        &out_len
    );

    if (ds != SCHC_OK) {
        zlog_error(error_cat, "SCHC decompress failed (status=%d)", (int)ds);
        return;
    }

    hex_dump(rx_cat, "SCHC OUT", out, out_len);
    zlog_info(rx_cat, "SCHC decompressed: %zu bytes", out_len);

    if (out_len != sizeof(sensor_data_t)) {
        zlog_warn(error_cat, "Unexpected decompressed size: %zu (expected %zu)",
                  out_len, sizeof(sensor_data_t));
        return;
    }

    sensor_data_t d;
    memcpy(&d, out, sizeof(d));
    log_sensor(rx_cat, &d);
}

int main(int argc, char *argv[])
{
    if (logger_init() != LOGGER_INIT_OK) {
        fprintf(stderr, "Logger initialization failed\n");
        return EXIT_FAILURE;
    }

    zlog_info(ok_cat, "Logger initialized");

    uint8_t id_arg = 0x00;
    uint8_t key_arg[KEY_SIZE];
    char *port = NULL;
    int32_t baudrate = 0;
    char *replay_hex = NULL;

    if (parse_cli_arguments(argc, argv,
                            &id_arg,
                            key_arg, KEY_SIZE,
                            &port,
                            &baudrate,
                            &replay_hex) != CLI_PARSE_OK) {
        zlog_error(error_cat, "Error parsing cli arguments");
        zlog_fini();
        return EXIT_FAILURE;
    }

    zlog_info(ok_cat, "Cli arg parse OK");
    zlog_info(ok_cat, "Receiver starting (id=%u)", (unsigned)id_arg);

    if (schc_service_init() != SCHC_OK) {
        zlog_error(error_cat, "SCHC init failed");
        zlog_fini();
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "SCHC service init OK");



    /* Normal mode: need a real modem */
    if (port == NULL || baudrate == 0) {
        zlog_error(error_cat, "Missing -p/--port or -b/--baud (or use --replay-hex)");
        zlog_fini();
        return EXIT_FAILURE;
    }

    int fd = open_serial_port((const uint8_t*)port, baudrate);
    if (fd < 0) {
        zlog_error(error_cat, "Error opening serial port");
        zlog_fini();
        return EXIT_FAILURE;
    }

    set_ahoi_id(fd, id_arg);

    zlog_info(ok_cat, "Layer 2 init OK (port=%s baud=115200 id=%u)", port, (unsigned)id_arg);
    zlog_info(ok_cat, "Looping receive_ahoi_packet_sync(); logging to rx.log");

    for (;;) {
        ahoi_packet_t pkt;
        ahoi_footer_t footer;

        memset(&pkt, 0, sizeof(pkt));
        memset(&footer, 0, sizeof(footer));

        const packet_rcv_status st = receive_ahoi_packet_sync(fd, &pkt, &footer, RX_TIMEOUT_MS);

        if (st == PACKET_RCV_TIMEOUT) {
            zlog_debug(ok_cat, "RX timeout");
            continue;
        }
        if (st != PACKET_RCV_OK) {
            zlog_warn(error_cat, "RX failed (status=%d)", (int)st);
            continue;
        }

        log_ahoi_packet(rx_cat, &pkt);

        if (pkt.payload == NULL || pkt.pl_size == 0) {
            zlog_warn(error_cat, "RX packet has empty payload");
            continue;
        }

        const size_t schc_in_len = (size_t)pkt.pl_size;
        if (schc_in_len > 512) {
            zlog_warn(error_cat, "SCHC payload too large: %zu", schc_in_len);
            continue;
        }

        uint8_t schc_in[512];
        memcpy(schc_in, pkt.payload, schc_in_len);

        handle_schc_and_log(schc_in, schc_in_len);
    }
}
