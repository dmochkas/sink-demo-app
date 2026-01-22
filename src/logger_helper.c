#include "sink_demo_app/logger_helper.h"

#include <stdio.h>
#include <string.h>

/* ------------------------ zlog categories ------------------------ */

zlog_category_t* ok_cat = NULL;
zlog_category_t* error_cat = NULL;
zlog_category_t* rx_cat = NULL;

logger_status logger_init(void)
{
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

    zlog_info(ok_cat, "Logger initialized");
    return LOGGER_INIT_OK;
}

/* ------------------------ generic logging helpers ------------------------ */

void hex_dump(zlog_category_t* cat, const char* prefix, const uint8_t* buf, size_t len)
{
    if (!cat || !prefix || (!buf && len)) return;

    char line[2048];
    size_t pos = 0;

    pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%s (%zu): ", prefix, len);
    for (size_t i = 0; i < len && pos + 4 < sizeof(line); i++) {
        pos += (size_t)snprintf(line + pos, sizeof(line) - pos, "%02x ", buf[i]);
    }

    zlog_info(cat, "%s", line);
}

void log_ahoi_packet(zlog_category_t* cat, const ahoi_packet_t* p)
{
    if (!cat || !p) return;

    zlog_info(cat,
              "AHOI RX: src=%u dst=%u type=%u flags=%u seq=%u pl_size=%u",
              p->src, p->dst, p->type, p->flags, p->seq, p->pl_size);
}

void log_sensor(zlog_category_t* cat, const sensor_data_t* d)
{
    if (!cat || !d) return;

    zlog_info(cat, "SENSOR: temp=%.3f pH=%.3f bat=%u",
              d->temp, d->pH, d->bat);
}

/* ------------------------ packet parsing + normalization ------------------------ */

#define IPV6_HDR_LEN 40
#define UDP_HDR_LEN  8

static inline uint16_t u16_be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline void put_u16_be(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF); }

static inline uint32_t sum16_add(uint32_t sum, uint16_t v)
{
    sum += v;
    return (sum & 0xFFFFu) + (sum >> 16);
}

static inline uint16_t ones_complement(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t udp_checksum_ipv6(const uint8_t src_ip[16],
                                  const uint8_t dst_ip[16],
                                  const uint8_t *udp,
                                  size_t udp_len)
{
    uint32_t sum = 0;

    for (int i = 0; i < 16; i += 2) sum = sum16_add(sum, (uint16_t)((src_ip[i] << 8) | src_ip[i + 1]));
    for (int i = 0; i < 16; i += 2) sum = sum16_add(sum, (uint16_t)((dst_ip[i] << 8) | dst_ip[i + 1]));

    /* UDP length (32-bit) */
    sum = sum16_add(sum, (uint16_t)((udp_len >> 16) & 0xFFFFu));
    sum = sum16_add(sum, (uint16_t)(udp_len & 0xFFFFu));

    /* next header = 17 (UDP) as 32-bit */
    sum = sum16_add(sum, 0x0000);
    sum = sum16_add(sum, 0x0011);

    /* UDP header + payload, checksum treated as zero */
    for (size_t i = 0; i + 1 < udp_len; i += 2) {
        uint16_t w = (i == 6) ? 0x0000 : (uint16_t)((udp[i] << 8) | udp[i + 1]);
        sum = sum16_add(sum, w);
    }

    if (udp_len & 1u) sum = sum16_add(sum, (uint16_t)(udp[udp_len - 1] << 8));

    uint16_t csum = ones_complement(sum);
    if (csum == 0x0000) csum = 0xFFFF;
    return csum;
}

static void ipv6_to_str(const uint8_t ip[16], char *out, size_t out_cap)
{
    (void)snprintf(out, out_cap,
                   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                   ip[0],ip[1],ip[2],ip[3],ip[4],ip[5],ip[6],ip[7],
                   ip[8],ip[9],ip[10],ip[11],ip[12],ip[13],ip[14],ip[15]);
}

int log_parsed_ipv6_udp_coap(const uint8_t *pkt, size_t pkt_len)
{
    if (!pkt || pkt_len < (IPV6_HDR_LEN + UDP_HDR_LEN + 4)) {
        zlog_error(error_cat, "IPv6/UDP/CoAP parse: packet too short (%zu)", pkt_len);
        return -1;
    }
    if ((pkt[0] >> 4) != 6) {
        zlog_error(error_cat, "IPv6 parse: wrong version");
        return -1;
    }

    const uint16_t ipv6_pl = u16_be(&pkt[4]);
    const uint8_t nh = pkt[6];
    const uint8_t hl = pkt[7];

    const uint8_t *src = &pkt[8];
    const uint8_t *dst = &pkt[24];

    char src_s[64], dst_s[64];
    ipv6_to_str(src, src_s, sizeof(src_s));
    ipv6_to_str(dst, dst_s, sizeof(dst_s));

    zlog_info(rx_cat, "IPv6: src=%s dst=%s payload_len=%u next_header=%u hop_limit=%u",
              src_s, dst_s, (unsigned)ipv6_pl, (unsigned)nh, (unsigned)hl);

    if (nh != 17) {
        zlog_error(error_cat, "IPv6 parse: next_header is not UDP (%u)", (unsigned)nh);
        return -1;
    }
    if (pkt_len < IPV6_HDR_LEN + ipv6_pl) {
        zlog_error(error_cat, "IPv6 parse: truncated packet (pkt_len=%zu ipv6_pl=%u)", pkt_len, (unsigned)ipv6_pl);
        return -1;
    }

    const uint8_t *udp = &pkt[IPV6_HDR_LEN];
    const uint16_t sport = u16_be(&udp[0]);
    const uint16_t dport = u16_be(&udp[2]);
    const uint16_t ulen  = u16_be(&udp[4]);
    const uint16_t ucsum = u16_be(&udp[6]);

    zlog_info(rx_cat, "UDP: src_port=%u dst_port=%u len=%u checksum=0x%04x",
              (unsigned)sport, (unsigned)dport, (unsigned)ulen, (unsigned)ucsum);

    if (ulen < UDP_HDR_LEN) {
        zlog_error(error_cat, "UDP parse: invalid length %u", (unsigned)ulen);
        return -1;
    }
    if (IPV6_HDR_LEN + ulen > pkt_len) {
        zlog_error(error_cat, "UDP parse: truncated udp (ulen=%u pkt_len=%zu)", (unsigned)ulen, pkt_len);
        return -1;
    }

    const uint8_t *coap = &udp[UDP_HDR_LEN];
    const size_t coap_len = (size_t)ulen - UDP_HDR_LEN;
    if (coap_len < 4) {
        zlog_error(error_cat, "CoAP parse: too short (%zu)", coap_len);
        return -1;
    }

    const uint8_t ver_type_tkl = coap[0];
    const uint8_t code = coap[1];
    const uint16_t mid = u16_be(&coap[2]);

    const uint8_t ver = (uint8_t)(ver_type_tkl >> 6);
    const uint8_t type = (uint8_t)((ver_type_tkl >> 4) & 0x03u);
    const uint8_t tkl = (uint8_t)(ver_type_tkl & 0x0Fu);

    if (ver != 1 || type != 1 || tkl != 0) {
        zlog_error(error_cat, "CoAP header mismatch (ver=%u type=%u tkl=%u)", ver, type, tkl);
        return -1;
    }

    size_t idx = 4;
    uint16_t opt_num = 0;
    bool saw_sensor = false;
    bool saw_data = false;

    while (idx < coap_len) {
        if (coap[idx] == 0xFF) { idx++; break; }

        const uint8_t opt = coap[idx++];
        const uint8_t delta = (uint8_t)(opt >> 4);
        const uint8_t len = (uint8_t)(opt & 0x0Fu);

        if (delta >= 13 || len >= 13) {
            zlog_error(error_cat, "CoAP option uses extended delta/len (delta=%u len=%u) not supported", delta, len);
            return -1;
        }

        opt_num = (uint16_t)(opt_num + delta);
        if (idx + len > coap_len) {
            zlog_error(error_cat, "CoAP option truncated");
            return -1;
        }

        if (opt_num == 11) {
            char v[32];
            const size_t cpy = len < (sizeof(v) - 1) ? len : (sizeof(v) - 1);
            memcpy(v, &coap[idx], cpy);
            v[cpy] = '\0';
            zlog_info(rx_cat, "CoAP option Uri-Path: '%s'", v);

            if (len == 6 && memcmp(&coap[idx], "sensor", 6) == 0) saw_sensor = true;
            if (len == 4 && memcmp(&coap[idx], "data", 4) == 0) saw_data = true;
        }

        idx += len;
    }

    zlog_info(rx_cat, "CoAP: code=0x%02x mid=0x%04x", code, mid);

    if (!saw_sensor || !saw_data) {
        zlog_error(error_cat, "CoAP options mismatch (sensor=%d data=%d)", (int)saw_sensor, (int)saw_data);
        return -1;
    }
    if (idx > coap_len) {
        zlog_error(error_cat, "CoAP parse: no payload marker");
        return -1;
    }

    const size_t payload_len = coap_len - idx;
    if (payload_len != sizeof(sensor_data_t)) {
        zlog_error(error_cat, "Unexpected CoAP payload size: %zu expected %zu", payload_len, sizeof(sensor_data_t));
        return -1;
    }

    sensor_data_t d;
    memcpy(&d, &coap[idx], sizeof(d));
    log_sensor(rx_cat, &d);

    return 0;
}

int normalize_ipv6_udp_coap_packet(const uint8_t *decomp, size_t decomp_len,
                                   uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!decomp || !out || !out_len) return -1;
    if (decomp_len < (IPV6_HDR_LEN + UDP_HDR_LEN + 4)) return -1;
    if ((decomp[0] >> 4) != 6) return -1;

    /* Canonical TX packet size in your template is 74 bytes */
    if (out_cap < 74) return -1;

    memcpy(out, decomp, IPV6_HDR_LEN);

    const uint8_t *udp_in = &decomp[IPV6_HDR_LEN];
    uint8_t *udp_out = &out[IPV6_HDR_LEN];

    memcpy(&udp_out[0], &udp_in[0], 4); /* ports */
    udp_out[4] = udp_out[5] = 0;
    udp_out[6] = udp_out[7] = 0;

    const uint8_t *coap_in = &udp_in[UDP_HDR_LEN];
    const size_t coap_in_len = decomp_len - (IPV6_HDR_LEN + UDP_HDR_LEN);
    if (coap_in_len < 4) return -1;

    uint8_t coap_tmp[256];
    size_t w = 0;
    memcpy(&coap_tmp[w], &coap_in[0], 4);
    w += 4;

    size_t idx = 4;
    while (idx < coap_in_len) {
        if (coap_in[idx] == 0xFF) { idx++; break; }

        const uint8_t opt = coap_in[idx++];
        const uint8_t delta = (uint8_t)(opt >> 4);
        const uint8_t len = (uint8_t)(opt & 0x0Fu);
        if (delta >= 13 || len >= 13) return -1;
        if (idx + len > coap_in_len) return -1;

        coap_tmp[w++] = opt;
        memcpy(&coap_tmp[w], &coap_in[idx], len);
        w += len;
        idx += len;
    }

    /* Insert marker and copy exactly sensor payload */
    coap_tmp[w++] = 0xFF;
    if (idx + sizeof(sensor_data_t) > coap_in_len) return -1;
    memcpy(&coap_tmp[w], &coap_in[idx], sizeof(sensor_data_t));
    w += sizeof(sensor_data_t);

    const uint16_t udp_len = (uint16_t)(UDP_HDR_LEN + w);
    const uint16_t ipv6_pl = udp_len;

    put_u16_be(&out[4], ipv6_pl);
    out[6] = 17;
    out[7] = 255;

    put_u16_be(&udp_out[4], udp_len);

    memcpy(&udp_out[UDP_HDR_LEN], coap_tmp, w);

    const uint8_t *src_ip = &out[8];
    const uint8_t *dst_ip = &out[24];
    const uint16_t csum = udp_checksum_ipv6(src_ip, dst_ip, udp_out, udp_len);
    put_u16_be(&udp_out[6], csum);

    *out_len = IPV6_HDR_LEN + (size_t)udp_len;
    return 0;
}
