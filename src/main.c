#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <ahoi_serial/ahoi_defs.h>
#include <ahoilib.h>
#include <ahoi_serial/com.h>   // receive_ahoi_packet_sync
#include <ahoi_serial/core.h>  // open_serial_port
#include <ahoi_serial/cmd.h>   // set_ahoi_id

#include "sink_demo_app/logger_helper.h"
#include "sink_demo_app/cli_helper.h"
#include "sink_demo_app/services/schc_service.h"
#include "sink_demo_app/services/sensor_service.h"

#ifndef RX_TIMEOUT_MS
#define RX_TIMEOUT_MS 1500
#endif

static void hex_dump(zlog_category_t* cat, const char* tag, const uint8_t* buf, size_t len)
{
    if (!cat || !tag) return;

    char line[2048];
    size_t pos = 0;

    pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%s (%zu): ", tag, len);
    for (size_t i = 0; i < len && pos + 4 < sizeof(line); i++) {
        pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%02x ", buf[i]);
    }

    zlog_info(cat, "%s", line);
}

static void log_ahoi_packet(zlog_category_t* cat, const ahoi_packet_t* p)
{
    if (!cat || !p) return;
    zlog_info(cat,
              "AHOI RX: src=%u dst=%u type=%u flags=%u seq=%u pl_size=%u",
              p->src, p->dst, p->type, p->flags, p->seq, p->pl_size);
}

static void log_sensor(zlog_category_t* cat, const sensor_data_t* d)
{
    if (!cat || !d) return;
    zlog_info(cat, "SENSOR: temp=%.3f pH=%.3f bat=%u", d->temp, d->pH, d->bat);
}

/* Parse:
 *   "96 97 f8 e6 ..."
 * or "9697f8e6..."
 */
static int parse_hex_string(const char* s, uint8_t* out, size_t out_cap, size_t* out_len)
{
    if (!s || !out || !out_len) return -1;

    size_t n = 0;
    const char* p = s;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;

        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        if (!isxdigit((unsigned char)p[0])) return -1;

        int hi = 0, lo = 0;
        char c0 = p[0];
        char c1 = p[1];

        if (isxdigit((unsigned char)c0) && isxdigit((unsigned char)c1)) {
            hi = (int)(isdigit((unsigned char)c0) ? c0 - '0' : (tolower((unsigned char)c0) - 'a' + 10));
            lo = (int)(isdigit((unsigned char)c1) ? c1 - '0' : (tolower((unsigned char)c1) - 'a' + 10));
            p += 2;
        } else {
            lo = (int)(isdigit((unsigned char)c0) ? c0 - '0' : (tolower((unsigned char)c0) - 'a' + 10));
            hi = 0;
            p += 1;
        }

        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == ',' || *p == ':') p++;

        if (n >= out_cap) return -2;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = n;
    return 0;
}

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
        zlog_error(rx_cat, "SCHC decompress failed (status=%d)", (int)ds);
        return;
    }

    hex_dump(rx_cat, "SCHC OUT", out, out_len);
    zlog_info(rx_cat, "SCHC decompressed: %zu bytes", out_len);

    if (out_len != sizeof(sensor_data_t)) {
        zlog_warn(rx_cat, "Unexpected decompressed size: %zu (expected %zu)",
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
    zlog_info(rx_cat, "Receiver starting (id=%u)", (unsigned)id_arg);

    if (schc_service_init() != SCHC_OK) {
        zlog_error(error_cat, "SCHC init failed");
        zlog_fini();
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "SCHC service init OK");

    /* Replay mode: decompress once and exit */
    if (replay_hex != NULL) {
        zlog_info(rx_cat, "Replay mode enabled (--replay-hex)");

        uint8_t schc_in[512];
        size_t schc_in_len = 0;

        const int pr = parse_hex_string(replay_hex, schc_in, sizeof(schc_in), &schc_in_len);
        if (pr != 0) {
            zlog_error(rx_cat, "Invalid --replay-hex payload");
            zlog_fini();
            return EXIT_FAILURE;
        }

        handle_schc_and_log(schc_in, schc_in_len);

        zlog_info(rx_cat, "Replay done, exiting.");
        zlog_fini();
        return EXIT_SUCCESS;
    }

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
    zlog_info(rx_cat, "Looping receive_ahoi_packet_sync(); logging to rx.log");

    for (;;) {
        ahoi_packet_t pkt;
        ahoi_footer_t footer;

        memset(&pkt, 0, sizeof(pkt));
        memset(&footer, 0, sizeof(footer));

        const packet_rcv_status st = receive_ahoi_packet_sync(fd, &pkt, &footer, RX_TIMEOUT_MS);

        if (st == PACKET_RCV_TIMEOUT) {
            zlog_debug(rx_cat, "RX timeout");
            continue;
        }
        if (st != PACKET_RCV_OK) {
            zlog_warn(rx_cat, "RX failed (status=%d)", (int)st);
            continue;
        }

        log_ahoi_packet(rx_cat, &pkt);

        if (pkt.payload == NULL || pkt.pl_size == 0) {
            zlog_warn(rx_cat, "RX packet has empty payload");
            continue;
        }

        const size_t schc_in_len = (size_t)pkt.pl_size;
        if (schc_in_len > 512) {
            zlog_warn(rx_cat, "SCHC payload too large: %zu", schc_in_len);
            continue;
        }

        uint8_t schc_in[512];
        memcpy(schc_in, pkt.payload, schc_in_len);

        handle_schc_and_log(schc_in, schc_in_len);
    }
}
