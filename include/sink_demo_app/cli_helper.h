#pragma once

#include <stdint.h>
#include <stddef.h>

typedef enum {
    CLI_PARSE_OK,
    CLI_PARSE_KO
} cli_parse_status;

cli_parse_status parse_cli_arguments(
    int argc,
    char *argv[],
    uint8_t *id,
    uint8_t *key_buf,
    size_t key_size,
    char **port,
    int32_t *baud,
    char **replay_hex
);
