/*
 * Shared stratum protocol selection and utility helpers for Primo ARM Miner.
 * Copyright (C) 2026 primo-arm-miner contributors.
 *
 * This file keeps the common encoding and target-conversion helpers used by
 * both the standard and Verus stratum front ends.
 * Substantially rewritten on 2026-03-16 from earlier GPL-licensed mining
 * software ancestry. See LICENSE and PROVENANCE.md.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "miner.h"
#include "stratum_internal.h"

static int decode_hex_nibble(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

static const struct stratum_protocol_ops standard_protocol_ops = {
    .handle_notify = stratum_notify_standard,
    .handle_set_target = NULL,
    .submit_share = stratum_submit_standard,
};

static const struct stratum_protocol_ops verus_protocol_ops = {
    .handle_notify = verus_stratum_notify,
    .handle_set_target = verus_stratum_set_target,
    .submit_share = verus_stratum_submit,
};

#ifdef PRIMO_RANDOMX
static const struct stratum_protocol_ops xmr_protocol_ops = {
    .handle_notify = xmr_stratum_handle_job,
    .handle_set_target = NULL,
    .submit_share = xmr_stratum_submit,
    .idle_keepalive = xmr_stratum_keepalive,
};
#endif

const struct stratum_protocol_ops *stratum_get_protocol_ops(const struct stratum_ctx *sctx)
{
    if (opt_algo == ALGO_VERUS || stratum_is_verus_protocol_load(sctx))
        return &verus_protocol_ops;

#ifdef PRIMO_RANDOMX
    if (opt_algo == ALGO_RANDOMX)
        return &xmr_protocol_ops;
#endif

    return &standard_protocol_ops;
}

bool stratum_json_array_append_string(json_t *array, const char *value)
{
    json_t *string_val;

    if (!array)
        return false;

    string_val = json_string(value ? value : "");
    if (!string_val)
        return false;

    return json_array_append_new(array, string_val) == 0;
}

bool stratum_decode_hex_field(void *output, const char *hexstr, size_t len, const char *context,
    const char *field_name)
{
    if (!hex2bin(output, hexstr, len)) {
        if (context && context[0])
            applog(LOG_ERR, "%s: invalid %s", context, field_name ? field_name : "field");
        else
            applog(LOG_ERR, "Invalid %s", field_name ? field_name : "field");
        return false;
    }

    return true;
}

/* struct work's job_id field is a fixed char[128] (include/miner.h). A job_id
 * at or beyond that length would be silently truncated by the later
 * snprintf(new_work->job_id, sizeof(new_work->job_id), "%s", ...) in each
 * protocol's build_*_work(), desyncing the ID we submit shares against from
 * what the pool tracks - exactly the failure mode the historical ccminer
 * "+8 skip" bug caused (see CLAUDE.md), just via truncation instead of an
 * offset. Reject the job update instead of silently mining against an ID we
 * already know we can't correctly round-trip. */
bool stratum_check_job_id_length(const char *job_id, const char *context)
{
    size_t max_len = sizeof(((struct work *)0)->job_id) - 1; /* reserve the NUL */

    if (!job_id || strlen(job_id) <= max_len)
        return true;

    applog(LOG_ERR, "%s: job_id too long (%zu chars, max %zu) - rejecting this job update",
           context && context[0] ? context : "Stratum notify", strlen(job_id), max_len);
    return false;
}

/* json_object_set_new() steals the reference to *value and decrements it even
 * on failure. Null the caller's handle up-front so the error-cleanup path can
 * never double-decref the (now freed or owned) value. Returns 0 on success. */
static int stratum_object_set_steal(json_t *obj, const char *key, json_t **value)
{
    json_t *v = *value;
    *value = NULL;
    return json_object_set_new(obj, key, v);
}

char *stratum_build_request_line(const char *method, uint32_t id, json_t *params)
{
    json_t *request = NULL;
    json_t *id_val = NULL;
    json_t *method_val = NULL;
    char *line = NULL;

    if (!method || !params) {
        if (params)
            json_decref(params);
        return NULL;
    }

    request = json_object();
    id_val = json_integer(id);
    method_val = json_string(method);
    if (!request || !id_val || !method_val)
        goto out;

    if (stratum_object_set_steal(request, "id", &id_val) != 0)
        goto out;

    if (stratum_object_set_steal(request, "method", &method_val) != 0)
        goto out;

    if (stratum_object_set_steal(request, "params", &params) != 0)
        goto out;

    line = json_dumps(request, 0);

out:
    if (id_val)
        json_decref(id_val);
    if (method_val)
        json_decref(method_val);
    if (params)
        json_decref(params);
    if (request)
        json_decref(request);

    return line;
}

char *stratum_build_submit_request_line(uint32_t submit_id, const char *user, const char *job_id,
    const char *param2, const char *param3, const char *param4)
{
    json_t *params = json_array();

    if (!params)
        return NULL;
    if (!stratum_json_array_append_string(params, user) ||
        !stratum_json_array_append_string(params, job_id) ||
        !stratum_json_array_append_string(params, param2) ||
        !stratum_json_array_append_string(params, param3) ||
        !stratum_json_array_append_string(params, param4)) {
        json_decref(params);
        return NULL;
    }

    return stratum_build_request_line("mining.submit", submit_id, params);
}

void cbin2hex(char *out, const char *in, size_t len)
{
    static const char hex_digits[] = "0123456789abcdef";

    if (!out)
        return;

    for (size_t byte_index = 0; byte_index < len; byte_index++) {
        uint8_t value = (uint8_t)in[byte_index];
        out[byte_index * 2] = hex_digits[value >> 4];
        out[byte_index * 2 + 1] = hex_digits[value & 0x0f];
    }
    out[len * 2] = '\0';
}

char *bin2hex(const unsigned char *in, size_t len)
{
    char *s = (char*)malloc((len * 2) + 1);
    if (!s)
        return NULL;
    cbin2hex(s, (const char *) in, len);
    return s;
}

bool hex2bin(void *output, const char *hexstr, size_t len)
{
    unsigned char *out = (unsigned char *)output;

    while (*hexstr && len) {
        int high_nibble;
        int low_nibble;

        if (!hexstr[1]) {
            applog(LOG_ERR, "hex2bin str truncated");
            return false;
        }

        high_nibble = decode_hex_nibble(hexstr[0]);
        low_nibble = decode_hex_nibble(hexstr[1]);
        if (high_nibble < 0 || low_nibble < 0) {
            char bad_byte[3];
            bad_byte[0] = hexstr[0];
            bad_byte[1] = hexstr[1];
            bad_byte[2] = '\0';
            applog(LOG_ERR, "hex2bin failed on '%s'", bad_byte);
            return false;
        }

        *out++ = (unsigned char)((high_nibble << 4) | low_nibble);
        hexstr += 2;
        len--;
    }

    return (len == 0 && *hexstr == 0) ? true : false;
}

void diff_to_target(uint32_t *target, double diff)
{
    static const double difficulty_word_base = 4294967296.0;
    static const double compact_target_base = 4294901760.0;
    double remaining_diff = diff;
    uint64_t compact_word;
    int target_word;

    for (target_word = 6; target_word > 0 && remaining_diff > 1.0; target_word--)
        remaining_diff /= difficulty_word_base;

    compact_word = (uint64_t)(compact_target_base / remaining_diff);
    if (compact_word == 0 && target_word == 6) {
        memset(target, 0xff, 32);
        return;
    }

    memset(target, 0, 32);
    target[target_word] = (uint32_t)compact_word;
    target[target_word + 1] = (uint32_t)(compact_word >> 32);
}

bool stratum_submit(struct pool_infos *pool, struct work *work)
{
    const struct stratum_protocol_ops *ops = stratum_get_protocol_ops(&pool->stratum);
    return ops->submit_share(pool, work);
}
