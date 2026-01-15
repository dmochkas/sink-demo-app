#include "sink_demo_app/l2/l2.h"

#include <string.h>
#include <stdbool.h>
#include <termios.h>

#include <ahoilib.h>

#include "sink_demo_app//logger_helper.h"

static int g_ahoi_fd = -1;
static const char* port = NULL;
static int32_t baudrate = -1;
static uint8_t modem_id = 0x00;
static uint32_t modem_id_32 = 0x00;

l2_init_status l2_init(void) {
    g_ahoi_fd = open_serial_port((const uint8_t*)port, baudrate);
    if (g_ahoi_fd == -1) {
        zlog_error(error_cat, "Error opening serial port");
        zlog_fini();
        return L2_INIT_ERROR;
    }

    tcflush(g_ahoi_fd, TCIFLUSH);
    set_ahoi_id(g_ahoi_fd, modem_id);
    // set_ahoi_sniff_mode(g_ahoi_fd, false);
    return L2_INIT_OK;
}

void l2_ahoi_set_port(const char* val) {
    port = val;
}

void l2_ahoi_set_baudrate(const int32_t val) {
    baudrate = val;
}

void l2_set_id(const uint32_t id) {
    modem_id = (uint8_t) id;
    modem_id_32 = id;
}

uint32_t* l2_get_id(void) {
    return &modem_id_32;
}

uint8_t* l2_get_id_byte(void) {
    return &modem_id;
}

void l2_recv_prepare(const void* params) {
    (void)params;
}

l2_recv_status l2_recv_run(uint8_t* payload, const size_t cap, size_t* out_len) {
    if (!payload || !out_len) return L2_RECV_KO;
    *out_len = 0;

    ahoi_packet_t p = {0};
    ahoi_footer_t f = {0};

    const packet_rcv_status st = receive_ahoi_packet_sync(g_ahoi_fd, &p, &f, 1500);

    if (st == PACKET_RCV_TIMEOUT) {
        return L2_RECV_TIMEOUT;
    }

    if (st != PACKET_RCV_OK) {
        return L2_RECV_KO;
    }

    // Log everything received (header-level)
    zlog_info(rx_cat, "AHOI RX: src=%u dst=%u type=%u flags=%u seq=%u pl_size=%u",
              p.src, p.dst, p.type, p.flags, p.seq, p.pl_size);

    if (!p.payload || p.pl_size == 0) {
        zlog_warn(rx_cat, "AHOI RX empty payload");
        return L2_RECV_KO;
    }

    if ((size_t)p.pl_size > cap) {
        zlog_warn(rx_cat, "AHOI RX payload too big: %u > %zu", p.pl_size, cap);
        return L2_RECV_KO;
    }

    memcpy(payload, p.payload, (size_t)p.pl_size);
    *out_len = (size_t)p.pl_size;

    return L2_RECV_OK;
}
