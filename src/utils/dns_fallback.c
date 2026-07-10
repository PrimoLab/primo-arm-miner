/*
 * Minimal DNS fallback resolver — see include/dns_fallback.h for when and
 * why this exists. A-record queries only, RFC 1035 wire format, message
 * compression handled on the parse side. Deliberately dependency-free.
 */

#include "dns_fallback.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define DNS_PORT            53
#define DNS_TIMEOUT_SEC     3
#define DNS_MAX_QUERY       300   /* header + 253-byte name + type/class */
#define DNS_MAX_RESPONSE    2048

/* Non-filtering public resolvers. Order matters: Cloudflare first (fastest
 * anycast, explicit no-filtering policy), Google second. Quad9 is
 * deliberately absent — it NXDOMAINs mining-pool hostnames. */
static const char *k_dns_servers[] = { "1.1.1.1", "8.8.8.8" };
#define DNS_NUM_SERVERS (sizeof(k_dns_servers) / sizeof(k_dns_servers[0]))

/* --- wire helpers ---------------------------------------------------------*/

static int dns_encode_qname(uint8_t *buf, size_t buf_len, const char *host)
{
    size_t host_len = strlen(host);
    size_t pos = 0, label_start = 0, i;

    if (host_len == 0 || host_len > 253 || buf_len < host_len + 2)
        return -1;

    for (i = 0; i <= host_len; i++) {
        if (i == host_len || host[i] == '.') {
            size_t label_len = i - label_start;
            if (label_len == 0 || label_len > 63)
                return -1;
            buf[pos++] = (uint8_t)label_len;
            memcpy(buf + pos, host + label_start, label_len);
            pos += label_len;
            label_start = i + 1;
        }
    }
    buf[pos++] = 0;
    return (int)pos;
}

static int dns_build_query(uint8_t *buf, size_t buf_len, const char *host,
                           uint16_t query_id)
{
    int qname_len;

    if (buf_len < 12)
        return -1;
    memset(buf, 0, 12);
    buf[0] = (uint8_t)(query_id >> 8);
    buf[1] = (uint8_t)(query_id & 0xFF);
    buf[2] = 0x01;              /* RD */
    buf[5] = 0x01;              /* QDCOUNT = 1 */

    qname_len = dns_encode_qname(buf + 12, buf_len - 12 - 4, host);
    if (qname_len < 0)
        return -1;

    buf[12 + qname_len + 0] = 0x00;  /* QTYPE  = A  */
    buf[12 + qname_len + 1] = 0x01;
    buf[12 + qname_len + 2] = 0x00;  /* QCLASS = IN */
    buf[12 + qname_len + 3] = 0x01;
    return 12 + qname_len + 4;
}

/* Advance past a (possibly compressed) name. Returns the next offset or -1. */
static int dns_skip_name(const uint8_t *msg, size_t msg_len, size_t pos)
{
    while (pos < msg_len) {
        uint8_t len = msg[pos];
        if (len == 0)
            return (int)(pos + 1);
        if ((len & 0xC0) == 0xC0)                 /* compression pointer */
            return (pos + 2 <= msg_len) ? (int)(pos + 2) : -1;
        if (len > 63)
            return -1;
        pos += 1 + len;
    }
    return -1;
}

/* Parse a response; on success writes the first A record to addr_out.
 * Returns 1 = found, 0 = valid response but no A record (or error rcode),
 * -1 = malformed / not ours, -2 = truncated (retry over TCP). */
static int dns_parse_response(const uint8_t *msg, size_t msg_len,
                              uint16_t query_id, struct in_addr *addr_out)
{
    uint16_t qdcount, ancount;
    int pos;
    uint16_t i;

    if (msg_len < 12)
        return -1;
    if (((uint16_t)msg[0] << 8 | msg[1]) != query_id)
        return -1;
    if (!(msg[2] & 0x80))                          /* QR must be set */
        return -1;
    if (msg[2] & 0x02)                             /* TC — truncated */
        return -2;
    if ((msg[3] & 0x0F) != 0)                      /* RCODE != NOERROR */
        return 0;

    qdcount = (uint16_t)msg[4] << 8 | msg[5];
    ancount = (uint16_t)msg[6] << 8 | msg[7];
    pos = 12;

    for (i = 0; i < qdcount; i++) {
        pos = dns_skip_name(msg, msg_len, (size_t)pos);
        if (pos < 0 || (size_t)pos + 4 > msg_len)
            return -1;
        pos += 4;                                  /* QTYPE + QCLASS */
    }

    for (i = 0; i < ancount; i++) {
        uint16_t rtype, rclass, rdlen;

        pos = dns_skip_name(msg, msg_len, (size_t)pos);
        if (pos < 0 || (size_t)pos + 10 > msg_len)
            return -1;
        rtype  = (uint16_t)msg[pos] << 8 | msg[pos + 1];
        rclass = (uint16_t)msg[pos + 2] << 8 | msg[pos + 3];
        rdlen  = (uint16_t)msg[pos + 8] << 8 | msg[pos + 9];
        pos += 10;
        if ((size_t)pos + rdlen > msg_len)
            return -1;
        if (rtype == 1 && rclass == 1 && rdlen == 4) {   /* A / IN */
            memcpy(&addr_out->s_addr, msg + pos, 4);
            return 1;
        }
        pos += rdlen;                              /* CNAME etc. — keep walking */
    }
    return 0;
}

/* --- transports -----------------------------------------------------------*/

static void dns_set_socket_timeouts(int fd)
{
    struct timeval tv = { DNS_TIMEOUT_SEC, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int dns_exchange_udp(const char *server, const uint8_t *query,
                            size_t query_len, uint8_t *resp, size_t resp_cap)
{
    struct sockaddr_in sa;
    ssize_t n;
    int fd;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1)
        return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    dns_set_socket_timeouts(fd);

    if (sendto(fd, query, query_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    /* connect()-less recvfrom: accept only a full datagram; the query-id
     * check in the parser rejects strays. */
    n = recv(fd, resp, resp_cap, 0);
    close(fd);
    return n > 0 ? (int)n : -1;
}

static int dns_exchange_tcp(const char *server, const uint8_t *query,
                            size_t query_len, uint8_t *resp, size_t resp_cap)
{
    struct sockaddr_in sa;
    uint8_t len_prefix[2];
    size_t got = 0, want;
    ssize_t n;
    int fd;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1)
        return -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    dns_set_socket_timeouts(fd);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        goto fail;

    len_prefix[0] = (uint8_t)(query_len >> 8);
    len_prefix[1] = (uint8_t)(query_len & 0xFF);
    if (send(fd, len_prefix, 2, 0) != 2 ||
        send(fd, query, query_len, 0) != (ssize_t)query_len)
        goto fail;

    while (got < 2) {
        n = recv(fd, len_prefix + got, 2 - got, 0);
        if (n <= 0)
            goto fail;
        got += (size_t)n;
    }
    want = (size_t)len_prefix[0] << 8 | len_prefix[1];
    if (want == 0 || want > resp_cap)
        goto fail;
    got = 0;
    while (got < want) {
        n = recv(fd, resp + got, want - got, 0);
        if (n <= 0)
            goto fail;
        got += (size_t)n;
    }
    close(fd);
    return (int)want;

fail:
    close(fd);
    return -1;
}

/* --- public entry point ---------------------------------------------------*/

int dns_fallback_resolve_ipv4(const char *host, char *ip_out, size_t ip_out_len)
{
    uint8_t query[DNS_MAX_QUERY];
    uint8_t resp[DNS_MAX_RESPONSE];
    struct in_addr addr;
    struct timespec ts;
    uint16_t query_id;
    int query_len;
    size_t s;

    if (!host || !host[0] || !ip_out || ip_out_len < INET_ADDRSTRLEN)
        return -1;

    /* Already an IPv4 literal — pass through. */
    if (inet_pton(AF_INET, host, &addr) == 1) {
        snprintf(ip_out, ip_out_len, "%s", host);
        return 0;
    }

    {
        const char *env = getenv("PRIMO_DNS_FALLBACK");
        if (env && env[0] == '0')
            return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &ts);
    query_id = (uint16_t)((ts.tv_nsec ^ (long)getpid()) & 0xFFFF);
    if (query_id == 0)
        query_id = 0x5150;   /* "PQ" — never send id 0 */

    query_len = dns_build_query(query, sizeof(query), host, query_id);
    if (query_len < 0)
        return -1;

    for (s = 0; s < DNS_NUM_SERVERS; s++) {
        int resp_len = dns_exchange_udp(k_dns_servers[s], query,
                                        (size_t)query_len, resp, sizeof(resp));
        int parsed = resp_len > 0
            ? dns_parse_response(resp, (size_t)resp_len, query_id, &addr)
            : -1;

        if (parsed == -2) {   /* truncated — same query over TCP */
            resp_len = dns_exchange_tcp(k_dns_servers[s], query,
                                        (size_t)query_len, resp, sizeof(resp));
            parsed = resp_len > 0
                ? dns_parse_response(resp, (size_t)resp_len, query_id, &addr)
                : -1;
        }

        if (parsed == 1) {
            if (!inet_ntop(AF_INET, &addr, ip_out, (socklen_t)ip_out_len))
                return -1;
            return 0;
        }
        /* parsed == 0 (authoritative no-A/NXDOMAIN) still falls through to
         * the next server: a filtering resolver answering NXDOMAIN is one of
         * the cases this fallback exists for. */
    }
    return -1;
}
