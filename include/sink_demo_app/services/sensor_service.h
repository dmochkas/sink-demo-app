#pragma once

#include <stdint.h>

typedef struct __attribute__((packed)) {
    float temp;
    float pH;
    uint8_t bat;
} sensor_data_t;
