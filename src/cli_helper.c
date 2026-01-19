#include "sink_demo_app/cli_helper.h"

#include <ctype.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

#include "sink_demo_app/logger_helper.h"

static int process_key_exact(const char *hex, uint8_t *key_buffer, size_t key_size)
{
    const size_t hex_len = strlen(hex);

    if (hex_len != key_size * 2) {
        zlog_error(error_cat, "Key must be exactly %zu hex characters", key_size * 2);
        return -1;
    }

    for (size_t i = 0; i < key_size; i++) {
        const char a = hex[i * 2];
        const char b = hex[i * 2 + 1];
        if (!isxdigit((unsigned char)a) || !isxdigit((unsigned char)b)) {
            zlog_error(error_cat, "Invalid hex characters in key");
            return -1;
        }
        sscanf(hex + i * 2, "%2hhx", &key_buffer[i]);
    }

    return 0;
}

cli_parse_status parse_cli_arguments(
    int argc,
    char *argv[],
    uint8_t *id,
    uint8_t *key_buf,
    size_t key_size,
    char **port,
    int32_t *baud,
    char **replay_hex)
{
    if (replay_hex) *replay_hex = NULL;

    static struct option options[] = {
        {"id",         required_argument, 0, 'i'},
        {"key",        required_argument, 0, 'k'},
        {"port",       required_argument, 0, 'p'},
        {"baud",       required_argument, 0, 'b'},
        {"replay-hex", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:k:p:b:r:", options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            if (id) *id = (uint8_t)atoi(optarg);
            break;

        case 'k':
            if (!key_buf) return CLI_PARSE_KO;
            if (process_key_exact(optarg, key_buf, key_size) != 0) return CLI_PARSE_KO;
            break;

        case 'p':
            if (port) *port = optarg;
            break;

        case 'b':
            if (!baud) return CLI_PARSE_KO;
            if (strcmp(optarg, "115200") != 0) {
                zlog_error(error_cat, "Only 115200 baudrate supported");
                return CLI_PARSE_KO;
            }
            *baud = B115200;
            break;

        case 'r':
            if (replay_hex) *replay_hex = optarg;
            break;

        default:
            return CLI_PARSE_KO;
        }
    }

    return CLI_PARSE_OK;
}
