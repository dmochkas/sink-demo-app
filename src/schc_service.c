#include <sink_demo_app/services/schc_service.h>

#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include <schc_sdk/fullsdknet.h>
#include <schc_sdk/schccomp.h>

#include "sink_demo_app/l2/l2.h"
#include <sink_demo_app/logger_helper.h>

#define NB_RULES 1
#define IPV6_UDP_RULE_ID 28

static uint8_t sensor_ip[16] = {
    0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01
};

static uint8_t sink_ip[16] = {
    0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x02,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x02
};

static uint8_t sensor_port[2] = { 0x12, 0x34 };
static uint8_t sink_port[2] = { 0x56, 0x78 };

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

/* same tpl_get_template_rules() as TX */
rules_t *tpl_get_template_rules(void)
{
    /* ===================== IPv6 / UDP RULE ===================== */
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

    static target_value_t dev_pref_tv = { TV_BIT_STRING, {{sensor_ip, 0, 64}} };
    static target_value_t dev_iid_tv  = { TV_BIT_STRING, {{sensor_ip+8, 0, 64}} };
    static target_value_t app_pref_tv = { TV_BIT_STRING, {{sink_ip, 0, 64}} };
    static target_value_t app_iid_tv  = { TV_BIT_STRING, {{sink_ip+8, 0, 64}} };

    static target_value_t dev_port_tv = { TV_BIT_STRING, {{sensor_port, 0, 16}} };
    static target_value_t app_port_tv = { TV_BIT_STRING, {{sink_port, 0, 16}} };

    static rule_field_t f0  = { FID_IPV6_VERSION, 1, DIR_BI, &ipv6_version_tv, 4,  MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f1  = { FID_IPV6_TRAFFIC_CLASS,1,DIR_BI,&ipv6_tc_tv,8,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f2  = { FID_IPV6_FLOW_LABEL,1,DIR_BI,&ipv6_fl_tv,20,MO_IGNORE,{0},CDA_NOT_SENT };
    static rule_field_t f3  = { FID_IPV6_PAYLOAD_LENGTH,1,DIR_BI,NULL,16,MO_IGNORE,{0},CDA_COMPUTE_LENGTH };
    static rule_field_t f4  = { FID_IPV6_NEXT_HEADER,1,DIR_BI,&ipv6_nh_tv,8,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f5  = { FID_IPV6_HOP_LIMIT,1,DIR_BI,&ipv6_hl_tv,8,MO_IGNORE,{0},CDA_NOT_SENT };
    static rule_field_t f6  = { FID_IPV6_PREFIX_DEV,1,DIR_BI,&dev_pref_tv,64,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f7  = { FID_IPV6_IID_DEV,1,DIR_BI,&dev_iid_tv,64,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f8  = { FID_IPV6_PREFIX_APP,1,DIR_BI,&app_pref_tv,64,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f9  = { FID_IPV6_IID_APP,1,DIR_BI,&app_iid_tv,64,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f10 = { FID_UDP_PORT_DEV,1,DIR_BI,&dev_port_tv,16,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f11 = { FID_UDP_PORT_APP,1,DIR_BI,&app_port_tv,16,MO_EQUAL,{0},CDA_NOT_SENT };
    static rule_field_t f12 = { FID_UDP_LENGTH,1,DIR_BI,NULL,16,MO_IGNORE,{0},CDA_COMPUTE_LENGTH };
    static rule_field_t f13 = { FID_UDP_CHECKSUM,1,DIR_BI,NULL,16,MO_IGNORE,{0},CDA_COMPUTE_CHECKSUM };

    static rule_field_t *ipv6udp_fields[14];
    static rule_t ipv6udp_rule;

    init_rule(&ipv6udp_rule, IPV6_UDP_RULE_ID, STACK_IPV6_UDP, ipv6udp_fields);
    add_rule_field(&ipv6udp_rule,&f0); add_rule_field(&ipv6udp_rule,&f1);
    add_rule_field(&ipv6udp_rule,&f2); add_rule_field(&ipv6udp_rule,&f3);
    add_rule_field(&ipv6udp_rule,&f4); add_rule_field(&ipv6udp_rule,&f5);
    add_rule_field(&ipv6udp_rule,&f6); add_rule_field(&ipv6udp_rule,&f7);
    add_rule_field(&ipv6udp_rule,&f8); add_rule_field(&ipv6udp_rule,&f9);
    add_rule_field(&ipv6udp_rule,&f10);add_rule_field(&ipv6udp_rule,&f11);
    add_rule_field(&ipv6udp_rule,&f12);add_rule_field(&ipv6udp_rule,&f13);



    /* ===================== RULE SET ===================== */
    static rules_t rules;
    static rule_t *rule_array[NB_RULES];

    init_rules(&rules, rule_array, IPV6_UDP_RULE_ID);
    add_rule(&rules, &ipv6udp_rule);

    return &rules;
}

schc_status_t schc_service_init(void)
{
    g_rules = tpl_get_template_rules();
    return SCHC_OK;
}

schc_status_t schc_service_decompress(const uint8_t *in, size_t in_len,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
    if (!in || !out || !out_len) return SCHC_ERR;
    if (in_len > UINT16_MAX || out_cap > UINT16_MAX) return SCHC_ERR;

    if (g_rules == NULL) {
        zlog_error(error_cat, "SCHC is not initialized");
        return SCHC_ERR;
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
