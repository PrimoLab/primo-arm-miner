/*
 * Minimal DNS fallback resolver — see include/dns_fallback.h for when and
 * why this exists, and how it mirrors the proxy's dial.go fallback policy
 * (all addresses returned, AAAA as last resort, one bounded time budget).
 * RFC 1035 wire format, message compression handled on the parse side.
 * Deliberately dependency-free.
 */

#include "dns_fallback.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* From miner.cpp (C linkage via miner.h's extern "C"); declared here rather
 * than pulling the whole miner.h surface into this dependency-free TU. */
extern bool miner_should_abort(void);

#define DNS_PORT            53
#define DNS_TIMEOUT_SEC     3     /* per-exchange cap (also clamped to budget) */
#define DNS_TOTAL_BUDGET_SEC 10   /* the ENTIRE walk shares this budget */
#define DNS_MAX_QUERY       300   /* header + 253-byte name + type/class */
#define DNS_MAX_RESPONSE    2048
#define DNS_QTYPE_A         1
#define DNS_QTYPE_AAAA      28
#define DNS_MAX_SERVERS     4

/* Non-filtering public resolvers. Order matters: Cloudflare first (fastest
 * anycast, explicit no-filtering policy), Google second. Quad9 is
 * deliberately absent — it NXDOMAINs mining-pool hostnames. */
static const char *k_dns_servers[] = { "1.1.1.1", "8.8.8.8" };
#define DNS_NUM_SERVERS (sizeof(k_dns_servers) / sizeof(k_dns_servers[0]))

/* --- deadline helpers ------------------------------------------------------*/

static void dns_deadline_init(struct timespec *deadline)
{
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += DNS_TOTAL_BUDGET_SEC;
}

/* Seconds left in the budget (0 = expired), also 0 once shutdown begins so
 * a closing miner never waits out the DNS walk. */
static int dns_budget_remaining(const struct timespec *deadline)
{
    struct timespec now;

    if (miner_should_abort())
        return 0;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec > deadline->tv_sec ||
        (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec))
        return 0;
    return (int)(deadline->tv_sec - now.tv_sec) + 1;
}

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
                           uint16_t query_id, uint16_t qtype)
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

    buf[12 + qname_len + 0] = (uint8_t)(qtype >> 8);
    buf[12 + qname_len + 1] = (uint8_t)(qtype & 0xFF);
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

/* Parse a response; appends EVERY matching address record (A for qtype A,
 * AAAA for qtype AAAA — pools run round-robin DNS, and the first record may
 * be the dead one) as text to ips[] until max_ips.
 * Returns 1 = at least one appended (count updated), 0 = valid response but
 * no matching record (or error rcode), -1 = malformed / not ours,
 * -2 = truncated (retry over TCP). */
static int dns_parse_response(const uint8_t *msg, size_t msg_len,
                              const uint8_t *query, size_t query_len,
                              uint16_t qtype,
                              char ips[][DNS_FALLBACK_ADDRSTRLEN],
                              int max_ips, int *count)
{
    uint16_t qdcount, ancount;
    int pos, found = 0;
    uint16_t i;

    if (msg_len < 12)
        return -1;
    if (msg[0] != query[0] || msg[1] != query[1])  /* transaction id */
        return -1;
    if (!(msg[2] & 0x80))                          /* QR must be set */
        return -1;
    if (msg[2] & 0x02)                             /* TC — truncated */
        return -2;

    qdcount = (uint16_t)msg[4] << 8 | msg[5];
    ancount = (uint16_t)msg[6] << 8 | msg[7];

    /* The response must echo our exact question: QDCOUNT=1 and identical
     * qname/qtype/qclass bytes (the question section is never compressed —
     * there is nothing earlier in the message to point into). Together with
     * the connected UDP socket this rejects forged answers that guessed the
     * port + 16-bit id but not the queried name. Checked before RCODE so a
     * spoofed NXDOMAIN can't end the resolver-fallback walk either. */
    if (qdcount != 1)
        return -1;
    if (msg_len < query_len || memcmp(msg + 12, query + 12, query_len - 12) != 0)
        return -1;

    if ((msg[3] & 0x0F) != 0)                      /* RCODE != NOERROR */
        return 0;

    pos = 12;

    for (i = 0; i < qdcount; i++) {
        pos = dns_skip_name(msg, msg_len, (size_t)pos);
        if (pos < 0 || (size_t)pos + 4 > msg_len)
            return -1;
        pos += 4;                                  /* QTYPE + QCLASS */
    }

    for (i = 0; i < ancount && *count < max_ips; i++) {
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
        if (rclass == 1 && qtype == DNS_QTYPE_A &&
            rtype == DNS_QTYPE_A && rdlen == 4) {
            struct in_addr a4;
            memcpy(&a4.s_addr, msg + pos, 4);
            if (inet_ntop(AF_INET, &a4, ips[*count], DNS_FALLBACK_ADDRSTRLEN)) {
                (*count)++;
                found = 1;
            }
        } else if (rclass == 1 && qtype == DNS_QTYPE_AAAA &&
                   rtype == DNS_QTYPE_AAAA && rdlen == 16) {
            struct in6_addr a6;
            memcpy(&a6, msg + pos, 16);
            if (inet_ntop(AF_INET6, &a6, ips[*count], DNS_FALLBACK_ADDRSTRLEN)) {
                (*count)++;
                found = 1;
            }
        }
        pos += rdlen;                              /* CNAME etc. — keep walking */
    }
    return found ? 1 : 0;
}

/* --- transports -----------------------------------------------------------*/

static void dns_set_socket_timeouts(int fd, int seconds)
{
    struct timeval tv = { seconds, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Per-op timeout: the usual 3 s, but never longer than the remaining walk
 * budget. remaining == 0 means the budget is spent — don't start. */
static int dns_op_timeout(const struct timespec *deadline)
{
    int remaining = dns_budget_remaining(deadline);
    if (remaining <= 0)
        return 0;
    return remaining < DNS_TIMEOUT_SEC ? remaining : DNS_TIMEOUT_SEC;
}

static int dns_exchange_udp(const char *server, const uint8_t *query,
                            size_t query_len, uint8_t *resp, size_t resp_cap,
                            const struct timespec *deadline)
{
    struct sockaddr_in sa;
    ssize_t n;
    int fd, op_timeout;

    op_timeout = dns_op_timeout(deadline);
    if (op_timeout <= 0)
        return -1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1)
        return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    dns_set_socket_timeouts(fd, op_timeout);

    /* connect() the UDP socket so the kernel only delivers datagrams from
     * the queried resolver — an unconnected recv() accepted a spoofed
     * answer from ANY source that guessed the ephemeral port, leaving only
     * the 16-bit transaction id as protection. */
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        send(fd, query, query_len, 0) < 0) {
        close(fd);
        return -1;
    }
    n = recv(fd, resp, resp_cap, 0);
    close(fd);
    return n > 0 ? (int)n : -1;
}

static int dns_exchange_tcp(const char *server, const uint8_t *query,
                            size_t query_len, uint8_t *resp, size_t resp_cap,
                            const struct timespec *deadline)
{
    struct sockaddr_in sa;
    uint8_t len_prefix[2];
    size_t got = 0, want;
    ssize_t n;
    int fd, op_timeout;

    op_timeout = dns_op_timeout(deadline);
    if (op_timeout <= 0)
        return -1;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1)
        return -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    dns_set_socket_timeouts(fd, op_timeout);

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

/* --- server list -----------------------------------------------------------*/

/* Default public resolvers, or the PRIMO_DNS_SERVERS override (comma-
 * separated IPv4 literals; test/field-debug hook). Returns the count. */
static int dns_get_servers(const char *servers[DNS_MAX_SERVERS],
                           char storage[DNS_MAX_SERVERS][INET_ADDRSTRLEN])
{
    const char *env = getenv("PRIMO_DNS_SERVERS");
    int n = 0;

    if (env && env[0]) {
        while (*env && n < DNS_MAX_SERVERS) {
            const char *sep = strchr(env, ',');
            size_t len = sep ? (size_t)(sep - env) : strlen(env);
            struct in_addr probe;

            if (len > 0 && len < INET_ADDRSTRLEN) {
                memcpy(storage[n], env, len);
                storage[n][len] = '\0';
                if (inet_pton(AF_INET, storage[n], &probe) == 1) {
                    servers[n] = storage[n];
                    n++;
                }
            }
            if (!sep)
                break;
            env = sep + 1;
        }
        if (n > 0)
            return n;
        /* Malformed override — fall through to the defaults. */
    }

    for (n = 0; n < (int)DNS_NUM_SERVERS; n++)
        servers[n] = k_dns_servers[n];
    return n;
}

/* --- lookup walk -----------------------------------------------------------*/

/* One qtype across every server (UDP, TCP on truncation) under the shared
 * deadline. Appends to ips[] / count; stops at the first server that yields
 * an answer for this qtype. */
static void dns_query_servers(const char *servers[], int num_servers,
                              const char *host, uint16_t qtype,
                              const struct timespec *deadline,
                              char ips[][DNS_FALLBACK_ADDRSTRLEN],
                              int max_ips, int *count)
{
    uint8_t query[DNS_MAX_QUERY];
    uint8_t resp[DNS_MAX_RESPONSE];
    uint16_t query_id;
    int query_len;
    int s;

    /* Unpredictable transaction id from the kernel CSPRNG; the clock^pid
     * mix is only the fallback if /dev/urandom is somehow unreadable. */
    {
        int rfd = open("/dev/urandom", O_RDONLY);
        ssize_t got = -1;
        if (rfd >= 0) {
            got = read(rfd, &query_id, sizeof(query_id));
            close(rfd);
        }
        if (got != (ssize_t)sizeof(query_id)) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            query_id = (uint16_t)((ts.tv_nsec ^ (long)getpid()) & 0xFFFF);
        }
    }
    if (query_id == 0)
        query_id = 0x5150;   /* "PQ" — never send id 0 */

    query_len = dns_build_query(query, sizeof(query), host, query_id, qtype);
    if (query_len < 0)
        return;

    for (s = 0; s < num_servers && *count < max_ips; s++) {
        int resp_len, parsed;

        if (dns_budget_remaining(deadline) <= 0)
            return;

        resp_len = dns_exchange_udp(servers[s], query, (size_t)query_len,
                                    resp, sizeof(resp), deadline);
        parsed = resp_len > 0
            ? dns_parse_response(resp, (size_t)resp_len, query,
                                 (size_t)query_len, qtype, ips, max_ips, count)
            : -1;

        if (parsed == -2) {   /* truncated — same query over TCP */
            resp_len = dns_exchange_tcp(servers[s], query, (size_t)query_len,
                                        resp, sizeof(resp), deadline);
            parsed = resp_len > 0
                ? dns_parse_response(resp, (size_t)resp_len, query,
                                     (size_t)query_len, qtype, ips, max_ips,
                                     count)
                : -1;
        }

        if (parsed == 1)
            return;   /* got addresses from this server — done for this qtype */
        /* parsed == 0 (authoritative no-record/NXDOMAIN) still falls through
         * to the next server: a filtering resolver answering NXDOMAIN is one
         * of the cases this fallback exists for. */
    }
}

/* --- public entry point ---------------------------------------------------*/

int dns_fallback_resolve(const char *host,
                         char ips[][DNS_FALLBACK_ADDRSTRLEN], int max_ips)
{
    const char *servers[DNS_MAX_SERVERS];
    char server_storage[DNS_MAX_SERVERS][INET_ADDRSTRLEN];
    struct timespec deadline;
    struct in_addr addr4;
    struct in6_addr addr6;
    int num_servers, count = 0;

    if (!host || !host[0] || !ips || max_ips < 1)
        return -1;

    /* Already an address literal — pass through as a single entry. */
    if (inet_pton(AF_INET, host, &addr4) == 1 ||
        inet_pton(AF_INET6, host, &addr6) == 1) {
        snprintf(ips[0], DNS_FALLBACK_ADDRSTRLEN, "%s", host);
        return 1;
    }

    {
        const char *env = getenv("PRIMO_DNS_FALLBACK");
        if (env && env[0] == '0')
            return -1;
    }

    num_servers = dns_get_servers(servers, server_storage);
    dns_deadline_init(&deadline);

    dns_query_servers(servers, num_servers, host, DNS_QTYPE_A,
                      &deadline, ips, max_ips, &count);
    /* AAAA is strictly a last resort (v6-only pools): phones' v6 routes are
     * the flakier path, so a host with ANY A record stays IPv4-only here. */
    if (count == 0)
        dns_query_servers(servers, num_servers, host, DNS_QTYPE_AAAA,
                          &deadline, ips, max_ips, &count);

    return count > 0 ? count : -1;
}
