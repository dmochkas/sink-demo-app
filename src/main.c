#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sink_demo_app/logger_helper.h"
#include "sink_demo_app/cli_helper.h"
#include "sink_demo_app/services/schc_service.h"
#include "sink_demo_app/l2/l2.h"

#define RX_BUF_CAP 1024
#define SCHC_BUF_CAP 512
#define NORM_BUF_CAP 256

static void handle_one_schc_frame(const uint8_t *schc_in, size_t schc_in_len)
{
    if (!schc_in || schc_in_len == 0) {
        zlog_error(error_cat, "Empty SCHC input");
        return;
    }

    /* rx_cat: what we received */
    hex_dump(rx_cat, "SCHC IN", schc_in, schc_in_len);

    uint8_t decomp[RX_BUF_CAP];
    size_t decomp_len = 0;

    const schc_status_t st = schc_service_decompress(
        schc_in, schc_in_len,
        decomp, sizeof(decomp),
        &decomp_len
    );

    if (st != SCHC_OK) {
        zlog_error(error_cat, "SCHC decompress failed (status=%d)", (int)st);
        return;
    }

    /* Always produce normalized wire packet */
    uint8_t norm[NORM_BUF_CAP];
    size_t norm_len = 0;

    if (normalize_ipv6_udp_coap_packet(decomp, decomp_len, norm, sizeof(norm), &norm_len) != 0) {
        zlog_error(error_cat, "Normalization failed (decomp_len=%zu)", decomp_len);
        return;
    }

    /* rx_cat: normalized wire bytes */
    hex_dump(rx_cat, "DECOMPRESSED OUT (IPv6/UDP/CoAP)", norm, norm_len);

    /* rx_cat: parsed content (IPv6/UDP/CoAP + sensor) */
    if (log_parsed_ipv6_udp_coap(norm, norm_len) != 0) {
        zlog_error(error_cat, "Failed to parse normalized IPv6/UDP/CoAP");
        return;
    }
}

int main(int argc, char *argv[])
{
    if (logger_init() != LOGGER_INIT_OK) {
        fprintf(stderr, "Logger initialization failed\n");
        return EXIT_FAILURE;
    }

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

    /* Replay is not allowed in final code */
    if (replay_hex != NULL) {
        zlog_error(error_cat, "--replay-hex is not supported in final build");
        zlog_fini();
        return EXIT_FAILURE;
    }

    zlog_info(ok_cat, "Receiver starting (id=%u)", (unsigned)id_arg);

    l2_set_id((uint32_t)id_arg);

#ifdef L2_AHOI_EXT
    l2_ahoi_set_port(port);
    l2_ahoi_set_baudrate(baudrate);
#endif

    if (l2_init() != L2_INIT_OK) {
        zlog_error(error_cat, "Layer 2 init failed");
        zlog_fini();
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "Layer 2 initialized");

    if (schc_service_init() != SCHC_OK) {
        zlog_error(error_cat, "SCHC init failed");
        zlog_fini();
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "SCHC service initialized");

    zlog_info(ok_cat, "Waiting for packets...");

    uint8_t schc_in[SCHC_BUF_CAP];
    size_t schc_in_len = 0;

    for (;;) {
        schc_in_len = 0;

        const l2_recv_status r = l2_recv_run(schc_in, sizeof(schc_in), &schc_in_len);

        if (r == L2_RECV_TIMEOUT) {
            /* Print every timeout (will be noisy). */
            zlog_debug(ok_cat, "RX timeout (no packet)");
            continue;
        }

        if (r != L2_RECV_OK) {
            zlog_error(error_cat, "L2 receive failed");
            continue;
        }

        /* schc_in is the SCHC frame payload */
        handle_one_schc_frame(schc_in, schc_in_len);
    }
}
