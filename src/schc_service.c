#include "sink_demo_app/services/schc_service.h"

#include <string.h>
#include <stdbool.h>

#include <schc_sdk/fullsdknet.h>
#include <schc_sdk/schccomp.h>

#include "sink_demo_app/l2/l2.h"
#include "sink_demo_app/logger_helper.h"

#define NB_RULES 1
#define NO_COMP_RULE_ID       150
#define IPV6_UDP_COAP_RULE_ID 28

/*
 * This SDK interprets DEV/APP relative to the node running the stack.
 * To reconstruct TX wire endpoints correctly on the sink, we swap:
 *   "dev_*" fields in rule context use sink endpoints (TX app)
 *   "app_*" fields in rule context use sensor endpoints (TX dev)
 *
 * Names exposed here are sensor/sink for clarity.
 */

/* TX sensor_ip = ...::1 ; TX sink_ip = ...::2 */
static uint8_t sensor_ip[16] = {
    0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01
};

static uint8_t sink_ip[16] = {
    0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x02,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x02
};

static uint8_t sensor_port[2] = { 0x12, 0x34 };
static uint8_t sink_port[2]   = { 0x56, 0x78 };

/* CoAP fixed */
static const uint8_t  k_coap_code = 0x02;          /* POST */
static const uint16_t k_coap_msg_id_base = 0x3030; /* upper 12 bits fixed */

static rules_t *g_rules = NULL;

static bool mocked_ext_compress(bit_buffer_t *output_bb_ptr, bit_string_t *input_bs_ptr)
{
    (void)output_bb_ptr;
    (void)input_bs_ptr;
    return true;
}

static bool mocked_ext_decompress(bit_buffer_t *p_out_data, bit_buffer_t *p_in_data)
{
    (void)p_out_data;
    (void)p_in_data;
    return true;
}

static bool l2a_get_dev_iid(uint8_t **iid)
{
    if (!iid) return false;
    *iid = l2_get_id_byte();
    return true;
}

rules_t *tpl_get_template_rules(void)
{
    /* ===================== IPv6 / UDP / CoAP RULE ===================== */

    /* ---------- IPv6 ---------- */

    static uint8_t ipv6_version = 0x60;
    static target_value_t ipv6_version_tv = { TV_BIT_STRING, {{&ipv6_version, 0, 4}} };

    static uint8_t ipv6_tc = 0;
    static target_value_t ipv6_tc_tv = { TV_BIT_STRING, {{&ipv6_tc, 0, 8}} };

    static uint8_t ipv6_fl[] = {0,0,0};
    static target_value_t ipv6_fl_tv = { TV_BIT_STRING, {{ipv6_fl, 0, 20}} };

    static uint8_t ipv6_nh = 17;
    static target_value_t ipv6_nh_tv = { TV_BIT_STRING, {{&ipv6_nh, 0, 8}} };

    static uint8_t ipv6_hl = 255;
    static target_value_t ipv6_hl_tv = { TV_BIT_STRING, {{&ipv6_hl, 0, 8}} };

    /*
     * DEV/APP swap for correct reconstruction:
     *   dev_*  = sink_*
     *   app_*  = sensor_*
     */
    static target_value_t dev_pref_tv = { TV_BIT_STRING, {{sink_ip, 0, 64}} };
    static target_value_t dev_iid_tv  = { TV_BIT_STRING, {{sink_ip + 8, 0, 64}} };
    static target_value_t app_pref_tv = { TV_BIT_STRING, {{sensor_ip, 0, 64}} };
    static target_value_t app_iid_tv  = { TV_BIT_STRING, {{sensor_ip + 8, 0, 64}} };

    /* ---------- UDP ---------- */

    static target_value_t dev_port_tv = { TV_BIT_STRING, {{sink_port, 0, 16}} };
    static target_value_t app_port_tv = { TV_BIT_STRING, {{sensor_port, 0, 16}} };

    /* ---------- CoAP fixed values ---------- */

    static uint8_t coap_version = 0x40;
    static target_value_t coap_version_tv = { TV_BIT_STRING, {{&coap_version, 0, 2}} };

    static uint8_t coap_type = 0x40; /* NON */
    static target_value_t coap_type_tv = { TV_BIT_STRING, {{&coap_type, 0, 2}} };

    static uint8_t coap_tkl = 0;
    static target_value_t coap_tkl_tv = { TV_BIT_STRING, {{&coap_tkl, 0, 4}} };

    static uint8_t coap_code = k_coap_code;
    static target_value_t coap_code_tv = { TV_BIT_STRING, {{&coap_code, 0, 8}} };

    static uint8_t coap_msg_id[2] = {
        (uint8_t)(k_coap_msg_id_base >> 8),
        (uint8_t)(k_coap_msg_id_base & 0xFFu)
    };
    static target_value_t coap_msg_id_tv = { TV_BIT_STRING, {{coap_msg_id, 0, 16}} };

    static uint8_t coap_uri_path_sensor[] = { 's','e','n','s','o','r' };
    static target_value_t coap_uri_path_sensor_tv = {
        TV_BIT_STRING, {{ coap_uri_path_sensor, 0, sizeof(coap_uri_path_sensor) * 8 }}
    };

    static uint8_t coap_uri_path_data[] = { 'd','a','t','a' };
    static target_value_t coap_uri_path_data_tv = {
        TV_BIT_STRING, {{ coap_uri_path_data, 0, sizeof(coap_uri_path_data) * 8 }}
    };

    static uint8_t coap_token_empty = 0x00;
    static target_value_t coap_token_empty_tv = { TV_BIT_STRING, {{&coap_token_empty, 0, 0}} };

    /* ---------- Rule fields ---------- */

    static rule_field_t f0  = { FID_IPV6_VERSION,        1, DIR_BI, &ipv6_version_tv, 4,  MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f1  = { FID_IPV6_TRAFFIC_CLASS,  1, DIR_BI, &ipv6_tc_tv,      8,  MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f2  = { FID_IPV6_FLOW_LABEL,     1, DIR_BI, &ipv6_fl_tv,      20, MO_IGNORE, {0}, CDA_NOT_SENT };
    static rule_field_t f3  = { FID_IPV6_PAYLOAD_LENGTH, 1, DIR_BI, NULL,             16, MO_IGNORE, {0}, CDA_COMPUTE_LENGTH };
    static rule_field_t f4  = { FID_IPV6_NEXT_HEADER,    1, DIR_BI, &ipv6_nh_tv,      8,  MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f5  = { FID_IPV6_HOP_LIMIT,      1, DIR_BI, &ipv6_hl_tv,      8,  MO_IGNORE, {0}, CDA_NOT_SENT };
    static rule_field_t f6  = { FID_IPV6_PREFIX_DEV,     1, DIR_BI, &dev_pref_tv,     64, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f7  = { FID_IPV6_IID_DEV,        1, DIR_BI, &dev_iid_tv,      64, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f8  = { FID_IPV6_PREFIX_APP,     1, DIR_BI, &app_pref_tv,     64, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f9  = { FID_IPV6_IID_APP,        1, DIR_BI, &app_iid_tv,      64, MO_EQUAL,  {0}, CDA_NOT_SENT };

    static rule_field_t f10 = { FID_UDP_PORT_DEV,        1, DIR_BI, &dev_port_tv,     16, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f11 = { FID_UDP_PORT_APP,        1, DIR_BI, &app_port_tv,     16, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f12 = { FID_UDP_LENGTH,          1, DIR_BI, NULL,             16, MO_IGNORE, {0}, CDA_COMPUTE_LENGTH };
    static rule_field_t f13 = { FID_UDP_CHECKSUM,        1, DIR_BI, NULL,             16, MO_IGNORE, {0}, CDA_COMPUTE_CHECKSUM };

    static rule_field_t f14 = { FID_COAP_VERSION,        1, DIR_BI, &coap_version_tv, 2,  MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f15 = { FID_COAP_TYPE,           1, DIR_BI, &coap_type_tv,    2,  MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f16 = { FID_COAP_TOKEN_LENGTH,   1, DIR_BI, &coap_tkl_tv,     4,  MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f17 = { FID_COAP_CODE,           1, DIR_BI, &coap_code_tv,    8,  MO_EQUAL, {0}, CDA_NOT_SENT };

    static rule_field_t f18 = { FID_COAP_MSG_ID,         1, DIR_BI, &coap_msg_id_tv,  16, MO_MSB, {12}, CDA_LSB };

    static rule_field_t f19 = { FID_COAP_TOKEN,          1, DIR_BI, &coap_token_empty_tv, 0, MO_EQUAL, {0}, CDA_NOT_SENT };

    static rule_field_t f20 = { FID_COAP_URI_PATH,       1, DIR_BI, &coap_uri_path_sensor_tv, 0, MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f21 = { FID_COAP_URI_PATH,       2, DIR_BI, &coap_uri_path_data_tv,   0, MO_EQUAL, {0}, CDA_NOT_SENT };

    /* Carry remaining bytes */
    static rule_field_t f22_payload = { FID_PAYLOAD,      1, DIR_BI, NULL, 0xFFFF, MO_IGNORE, {0}, CDA_VALUE_SENT };

    static rule_field_t *fields[23];
    static rule_t rule;

    init_rule(&rule, IPV6_UDP_COAP_RULE_ID, STACK_IPV6_UDP_COAP, fields);

    add_rule_field(&rule,&f0);  add_rule_field(&rule,&f1);
    add_rule_field(&rule,&f2);  add_rule_field(&rule,&f3);
    add_rule_field(&rule,&f4);  add_rule_field(&rule,&f5);
    add_rule_field(&rule,&f6);  add_rule_field(&rule,&f7);
    add_rule_field(&rule,&f8);  add_rule_field(&rule,&f9);
    add_rule_field(&rule,&f10); add_rule_field(&rule,&f11);
    add_rule_field(&rule,&f12); add_rule_field(&rule,&f13);
    add_rule_field(&rule,&f14); add_rule_field(&rule,&f15);
    add_rule_field(&rule,&f16); add_rule_field(&rule,&f17);
    add_rule_field(&rule,&f18); add_rule_field(&rule,&f19);
    add_rule_field(&rule,&f20); add_rule_field(&rule,&f21);
    add_rule_field(&rule,&f22_payload);

    static rules_t rules;
    static rule_t *rule_array[NB_RULES];

    init_rules(&rules, rule_array, NO_COMP_RULE_ID);
    add_rule(&rules, &rule);

    return &rules;
}

schc_status_t schc_service_init(void)
{
    g_rules = tpl_get_template_rules();
    zlog_info(ok_cat, "SCHC rules initialized (default_rule_id=%u)", (unsigned)NO_COMP_RULE_ID);
    return SCHC_OK;
}

schc_status_t schc_service_decompress(const uint8_t *in, size_t in_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
    if (!in || !out || !out_len) return SCHC_ERR;
    if (in_len == 0) return SCHC_ERR;
    if (in_len > UINT16_MAX || out_cap > UINT16_MAX) return SCHC_ERR;

    if (!g_rules) {
        zlog_error(error_cat, "SCHC is not initialized");
        return SCHC_ERR;
    }

    /* No-compression frame: [rule_id][original bytes...] */
    if (in[0] == (uint8_t)NO_COMP_RULE_ID) {
        if (in_len < 2) return SCHC_ERR;
        if ((in_len - 1) > out_cap) return SCHC_BUF_TOO_SMALL;
        memcpy(out, in + 1, in_len - 1);
        *out_len = in_len - 1;
        zlog_info(ok_cat, "SCHC no-comp: passthrough %zu bytes", *out_len);
        return SCHC_OK;
    }

    uint16_t decomp_size = 0;

    comp_callbacks_t cb = {0};
    cb.ext_compress   = mocked_ext_compress;
    cb.ext_decompress = mocked_ext_decompress;
    cb.get_dev_iid    = l2a_get_dev_iid;

    const comp_status_t st = schc_decompress(
        g_rules,
        out,
        (uint16_t)out_cap,
        &decomp_size,
        (uint8_t*)in,
        (uint16_t)in_len,
        &cb
    );

    if (st != COMP_SUCCESS) {
        zlog_error(error_cat, "SCHC decompress failed: %d", st);
        return SCHC_ERR;
    }

    *out_len = (size_t)decomp_size;
    zlog_info(ok_cat, "SCHC decompression successful (%zu bytes)", *out_len);
    return SCHC_OK;
}
