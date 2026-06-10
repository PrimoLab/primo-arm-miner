/*
 * Legacy-compatible monitoring API for Primo ARM Miner.
 * Copyright (C) 2026 primo-arm-miner contributors.
 *
 * Provides a read-focused ccminer-style TCP API so existing dashboards and
 * tooling can consume Primo runtime statistics without changing the mining
 * hot path or control-plane behavior.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "cpu_features.h"
#include "miner.h"
#include "stratum_internal.h"

#define API_VERSION "1.9"
#define API_BACKLOG 10
#define API_BUFFER_SIZE 16384
#define API_RECV_SIZE 1024
#define API_HISTORY_SIZE 50
#define API_CLIENT_INITIAL_READ_TIMEOUT_MS 1000
#define API_CLIENT_IDLE_READ_TIMEOUT_MS 200
#define API_CLIENT_WRITE_TIMEOUT_MS 1000

struct api_history_entry {
    int thread_id;
    uint32_t height;
    double khs;
    double diff;
    uint64_t hash_count;
    uint32_t id;
    time_t timestamp;
};

struct api_command {
    const char *name;
    char *(*handler)(char *out, size_t out_size, const char *params);
};

static pthread_mutex_t g_api_service_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_api_service_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_api_thread;
static bool g_api_thread_active = false;
static bool g_api_thread_join_pending = false;
static bool g_api_shutdown_requested = false;
static bool g_api_startup_complete = false;
static bool g_api_startup_succeeded = false;
static time_t g_api_startup_time = 0;
/* Port the listener actually bound to. May differ from the configured
 * opt_api_port when the default 4068 was busy and we probed upward. Kept
 * module-local so the API thread never writes the shared opt_* options. */
static int g_api_bound_port = 0;

static struct api_history_entry g_api_history[API_HISTORY_SIZE];
static size_t g_api_history_head = 0;
static size_t g_api_history_count = 0;
static uint32_t g_api_history_next_id = 1;
static uint64_t g_api_previous_hash_totals[MAX_THREADS];
static time_t g_api_last_history_sample = 0;

static char *build_summary_response(char *out, size_t out_size, const char *params);
static char *build_threads_response(char *out, size_t out_size, const char *params);
static char *build_pool_response(char *out, size_t out_size, const char *params);
static char *build_history_response(char *out, size_t out_size, const char *params);
static char *build_hwinfo_response(char *out, size_t out_size, const char *params);
static char *build_meminfo_response(char *out, size_t out_size, const char *params);
static char *build_scanlog_response(char *out, size_t out_size, const char *params);
static char *build_help_response(char *out, size_t out_size, const char *params);

static const struct api_command g_api_commands[] = {
    { "summary", build_summary_response },
    { "threads", build_threads_response },
    { "pool", build_pool_response },
    { "histo", build_history_response },
    { "hwinfo", build_hwinfo_response },
    { "meminfo", build_meminfo_response },
    { "scanlog", build_scanlog_response },
    { "help", build_help_response },
};

static size_t api_response_capacity(const struct api_command *command)
{
    size_t capacity = API_BUFFER_SIZE;

    if (!command)
        return capacity;

    if (command->handler == build_threads_response) {
        size_t thread_count = opt_n_threads > 0 ? (size_t)opt_n_threads : (size_t)MAX_THREADS;
        capacity = 1024 + thread_count * 512;
    } else if (command->handler == build_history_response) {
        capacity = 1024 + ((size_t)API_HISTORY_SIZE * 160);
    } else if (command->handler == build_help_response) {
        capacity = 1024 + ((size_t)(sizeof(g_api_commands) / sizeof(g_api_commands[0])) * 32);
    }

    return capacity > API_BUFFER_SIZE ? capacity : API_BUFFER_SIZE;
}

static bool api_shutdown_requested(void)
{
    bool requested;

    pthread_mutex_lock(&g_api_service_lock);
    requested = g_api_shutdown_requested;
    pthread_mutex_unlock(&g_api_service_lock);

    return requested;
}

static bool api_appendf(char *out, size_t out_size, size_t *pos, const char *fmt, ...)
{
    va_list ap;
    int written;

    if (!out || !pos || !fmt || *pos >= out_size)
        return false;

    va_start(ap, fmt);
    written = vsnprintf(out + *pos, out_size - *pos, fmt, ap);
    va_end(ap);

    if (written < 0)
        return false;
    if ((size_t)written >= out_size - *pos) {
        *pos = out_size;
        return false;
    }

    *pos += (size_t)written;
    return true;
}

static void api_reset_history(void)
{
    memset(g_api_history, 0, sizeof(g_api_history));
    memset(g_api_previous_hash_totals, 0, sizeof(g_api_previous_hash_totals));
    g_api_history_head = 0;
    g_api_history_count = 0;
    g_api_history_next_id = 1;
    g_api_last_history_sample = 0;
}

static void api_push_history_sample(const struct api_history_entry *entry)
{
    g_api_history[g_api_history_head] = *entry;
    g_api_history_head = (g_api_history_head + 1) % API_HISTORY_SIZE;
    if (g_api_history_count < API_HISTORY_SIZE)
        g_api_history_count++;
}

static void api_collect_history_sample(time_t now)
{
    struct miner_api_snapshot miner_snapshot;
    struct stratum_api_pool_snapshot pool_snapshot;
    int interval = opt_statsavg > 0 ? opt_statsavg : 30;

    if (interval < 1)
        interval = 1;

    if (g_api_last_history_sample != 0 &&
        difftime(now, g_api_last_history_sample) < interval) {
        return;
    }

    miner_get_api_snapshot(&miner_snapshot);
    stratum_get_api_pool_snapshot(miner_get_current_pool_index(), &pool_snapshot);

    for (int i = 0; i < miner_snapshot.thread_count && i < MAX_THREADS; i++) {
        struct api_history_entry entry;
        uint64_t total_hashes = miner_snapshot.threads[i].hashes_done_total;
        uint64_t previous_hashes = g_api_previous_hash_totals[i];

        memset(&entry, 0, sizeof(entry));
        entry.thread_id = i;
        entry.height = pool_snapshot.work_ready ? pool_snapshot.current_work.height : 0;
        entry.khs = miner_snapshot.threads[i].hashrate / 1000.0;
        entry.diff = pool_snapshot.work_ready ? pool_snapshot.current_work.targetdiff : 0.0;
        entry.hash_count = (total_hashes >= previous_hashes) ? (total_hashes - previous_hashes)
                                                             : total_hashes;
        entry.id = g_api_history_next_id++;
        entry.timestamp = now;

        g_api_previous_hash_totals[i] = total_hashes;
        api_push_history_sample(&entry);
    }

    g_api_last_history_sample = now;
}

static int api_find_max_cpu_freq_mhz(void)
{
    int max_freq_mhz = 0;

    for (int i = 0; i < g_num_cpus; i++) {
        int freq_mhz = g_cpu_cores[i].max_freq_khz / 1000;
        if (freq_mhz > max_freq_mhz)
            max_freq_mhz = freq_mhz;
    }

    return max_freq_mhz;
}

static const char *api_get_os_name(char *buffer, size_t buffer_size)
{
    struct utsname uts;

    if (!buffer || buffer_size == 0)
        return "unknown";

    if (uname(&uts) == 0) {
        snprintf(buffer, buffer_size, "%s %s", uts.sysname, uts.release);
        return buffer;
    }

    snprintf(buffer, buffer_size, "linux");
    return buffer;
}

static void api_trim_trailing_newlines(char *buffer)
{
    size_t len;

    if (!buffer)
        return;

    len = strlen(buffer);
    while (len > 0 && (buffer[len - 1] == '\n' || buffer[len - 1] == '\r')) {
        buffer[len - 1] = '\0';
        len--;
    }
}

static bool api_http_headers_complete(const char *request)
{
    return request &&
           (strstr(request, "\r\n\r\n") != NULL || strstr(request, "\n\n") != NULL);
}

static int api_wait_for_fd(int fd, bool want_write, int timeout_ms)
{
    if (fd < 0)
        return -1;

    while (1) {
        struct pollfd pfd;
        int ready;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = fd;
        pfd.events = want_write ? POLLOUT : POLLIN;

        ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0 && errno == EINTR)
            continue;

        return ready;
    }
}

static ssize_t api_recv_request(int fd, char *request, size_t request_size)
{
    size_t used = 0;
    bool is_http = false;

    if (!request || request_size < 2)
        return -1;

    request[0] = '\0';

    while (used + 1 < request_size) {
        int timeout_ms = used == 0 ? API_CLIENT_INITIAL_READ_TIMEOUT_MS
                                   : API_CLIENT_IDLE_READ_TIMEOUT_MS;
        ssize_t received;
        int ready = api_wait_for_fd(fd, false, timeout_ms);

        if (ready < 0)
            return -1;
        if (ready == 0)
            break;

        received = recv(fd, request + used, request_size - used - 1, 0);
        if (received < 0) {
            if (errno == EINTR)
                continue;
            if ((errno == EAGAIN || errno == EWOULDBLOCK) && used > 0)
                break;
            return -1;
        }
        if (received == 0)
            break;

        used += (size_t)received;
        request[used] = '\0';

        if (!is_http && used >= 5 && strncmp(request, "GET /", 5) == 0)
            is_http = true;
        if (is_http && api_http_headers_complete(request))
            break;
        if (!is_http && (strchr(request, '\n') || strchr(request, '\r')))
            break;
    }

    if (used + 1 >= request_size && opt_debug)
        applog(LOG_DEBUG, "API request filled the receive buffer and may be truncated");

    request[used] = '\0';
    return (ssize_t)used;
}

static bool api_send_all(int fd, const void *buffer, size_t length)
{
    const char *cursor = (const char *)buffer;
    size_t sent = 0;
    int send_flags = 0;

#ifdef MSG_NOSIGNAL
    send_flags |= MSG_NOSIGNAL;
#endif

    while (sent < length) {
        ssize_t rc = send(fd, cursor + sent, length - sent, send_flags);

        if (rc > 0) {
            sent += (size_t)rc;
            continue;
        }
        if (rc == 0)
            return false;
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int ready = api_wait_for_fd(fd, true, API_CLIENT_WRITE_TIMEOUT_MS);
            if (ready <= 0)
                return false;
            continue;
        }

        return false;
    }

    return true;
}

static const char *api_find_websocket_key(char *request)
{
    char *key;
    char *line_end;

    key = strstr(request, "Sec-WebSocket-Key:");
    if (!key)
        return NULL;

    key += strlen("Sec-WebSocket-Key:");
    while (*key == ' ')
        key++;

    line_end = strchr(key, '\r');
    if (!line_end)
        line_end = strchr(key, '\n');
    if (line_end)
        *line_end = '\0';

    return key;
}

static bool api_parse_http_get(char *request, char *command, size_t command_size,
                               char *params, size_t params_size, const char **websocket_key)
{
    char *path;
    char *path_end;
    char *slash;

    if (strncmp(request, "GET /", 5) != 0)
        return false;

    if (websocket_key)
        *websocket_key = api_find_websocket_key(request);

    path = request + 5;
    path_end = strchr(path, ' ');
    if (!path_end)
        return false;
    *path_end = '\0';

    slash = strchr(path, '/');
    if (slash) {
        *slash = '\0';
        slash++;
    }

    snprintf(command, command_size, "%s", path);
    if (slash && params && params_size > 0)
        snprintf(params, params_size, "%s", slash);
    else if (params && params_size > 0)
        params[0] = '\0';

    return command[0] != '\0';
}

static bool api_parse_command(char *request, char *command, size_t command_size,
                              char *params, size_t params_size, const char **websocket_key)
{
    char *separator;

    if (!request || !command || command_size == 0 || !params || params_size == 0)
        return false;

    command[0] = '\0';
    params[0] = '\0';
    if (websocket_key)
        *websocket_key = NULL;

    api_trim_trailing_newlines(request);

    if (api_parse_http_get(request, command, command_size, params, params_size, websocket_key))
        return true;

    separator = strchr(request, '|');
    if (separator) {
        *separator = '\0';
        separator++;
        snprintf(params, params_size, "%s", separator);
        if (params[0] != '\0') {
            size_t len = strlen(params);
            if (len > 0 && params[len - 1] == '|')
                params[len - 1] = '\0';
        }
    }

    snprintf(command, command_size, "%s", request);
    return command[0] != '\0';
}

static int api_send_response(int fd, const char *response)
{
    if (!response)
        return 0;

    return api_send_all(fd, response, strlen(response)) ? 0 : -1;
}

/* Minimal SHA-1 (RFC 3174) and base64, used only for the WebSocket upgrade
 * handshake (Sec-WebSocket-Accept). Replaces the former OpenSSL dependency —
 * the only two libcrypto calls in the project — so release binaries are not
 * tied to a specific libssl SONAME (1.1 vs 3 split across distro releases).
 * Not used for any mining-related hashing. */
#define API_SHA1_DIGEST_LENGTH 20

static void api_sha1(const unsigned char *data, size_t len, unsigned char digest[API_SHA1_DIGEST_LENGTH])
{
    uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };
    uint64_t bit_len = (uint64_t)len * 8;
    /* Message + 0x80 + zero pad + 8-byte length, in 64-byte blocks. The
     * handshake input is ~60 bytes, so a small stack buffer suffices. */
    size_t padded = ((len + 8) / 64 + 1) * 64;
    unsigned char block[64];

    for (size_t offset = 0; offset < padded; offset += 64) {
        for (size_t i = 0; i < 64; i++) {
            size_t pos = offset + i;
            if (pos < len)
                block[i] = data[pos];
            else if (pos == len)
                block[i] = 0x80;
            else if (pos >= padded - 8)
                block[i] = (unsigned char)(bit_len >> (8 * (padded - 1 - pos)));
            else
                block[i] = 0;
        }

        uint32_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
                   ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
        }
        for (int i = 16; i < 80; i++) {
            uint32_t v = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (v << 1) | (v >> 31);
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | ((~b) & d);         k = 0x5A827999u; }
            else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1u; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDCu; }
            else             { f = b ^ c ^ d;                    k = 0xCA62C1D6u; }
            uint32_t tmp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    for (int i = 0; i < 5; i++) {
        digest[i * 4]     = (unsigned char)(h[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(h[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(h[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)(h[i]);
    }
}

static void api_base64_encode(const unsigned char *in, size_t in_len, char *out)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, o = 0;

    for (i = 0; i + 2 < in_len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = tbl[(v >> 18) & 63]; out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];  out[o++] = tbl[v & 63];
    }
    if (i + 1 == in_len) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = tbl[(v >> 18) & 63]; out[o++] = tbl[(v >> 12) & 63];
        out[o++] = '='; out[o++] = '=';
    } else if (i + 2 == in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = tbl[(v >> 18) & 63]; out[o++] = tbl[(v >> 12) & 63];
        out[o++] = tbl[(v >> 6) & 63];  out[o++] = '=';
    }
    out[o] = '\0';
}

static int api_send_websocket_response(int fd, const char *response, const char *client_key)
{
    unsigned char digest[API_SHA1_DIGEST_LENGTH];
    unsigned char frame_header[10];
    char accept_input[128];
    char accept_key[64];
    char handshake[256];
    size_t payload_len;
    size_t header_len = 2;

    if (!response || !client_key)
        return -1;

    snprintf(accept_input, sizeof(accept_input), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", client_key);
    api_sha1((const unsigned char *)accept_input, strlen(accept_input), digest);
    api_base64_encode(digest, API_SHA1_DIGEST_LENGTH, accept_key);

    snprintf(handshake, sizeof(handshake),
             "HTTP/1.1 101 Switching Protocol\r\n"
             "Upgrade: WebSocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n"
             "Sec-WebSocket-Protocol: text\r\n"
             "\r\n",
             accept_key);

    payload_len = strlen(response);
    memset(frame_header, 0, sizeof(frame_header));
    frame_header[0] = 0x81;
    if (payload_len <= 125) {
        frame_header[1] = (unsigned char)payload_len;
    } else if (payload_len <= 65535) {
        frame_header[1] = 126;
        frame_header[2] = (unsigned char)(payload_len >> 8);
        frame_header[3] = (unsigned char)(payload_len & 0xff);
        header_len = 4;
    } else {
        frame_header[1] = 127;
        frame_header[2] = (unsigned char)(payload_len >> 56);
        frame_header[3] = (unsigned char)(payload_len >> 48);
        frame_header[4] = (unsigned char)(payload_len >> 40);
        frame_header[5] = (unsigned char)(payload_len >> 32);
        frame_header[6] = (unsigned char)(payload_len >> 24);
        frame_header[7] = (unsigned char)(payload_len >> 16);
        frame_header[8] = (unsigned char)(payload_len >> 8);
        frame_header[9] = (unsigned char)(payload_len & 0xff);
        header_len = 10;
    }

    if (!api_send_all(fd, handshake, strlen(handshake)))
        return -1;
    if (!api_send_all(fd, frame_header, header_len))
        return -1;
    return api_send_all(fd, response, payload_len) ? 0 : -1;
}

/* opt_api_bind defaults to NULL and can also be left NULL by an OOM in
 * replace_config_string. Resolve a safe default at every read so the API
 * never dereferences NULL (inet_pton/strcmp/log). */
static const char *api_bind_address(void)
{
    return (opt_api_bind && opt_api_bind[0]) ? opt_api_bind : "127.0.0.1";
}

static int api_open_listen_socket(void)
{
    int listen_fd;
    struct sockaddr_in address;
    const char *bind_addr = api_bind_address();
    int port = opt_api_port;
    int optval = 1;
    int flags;
    int port_probe_count = 0;

    if (port <= 0)
        return -1;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        applog(LOG_ERR, "API socket creation failed for %s:%d: %s",
               bind_addr, port, strerror(errno));
        return -1;
    }

    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0 && opt_debug)
        applog(LOG_DEBUG, "API SO_REUSEADDR failed (ignored): %s", strerror(errno));

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, bind_addr, &address.sin_addr) != 1) {
        applog(LOG_ERR, "API bind address is not a valid IPv4 address: %s", bind_addr);
        close(listen_fd);
        return -1;
    }

    while (1) {
        address.sin_port = htons((uint16_t)port);
        if (bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) == 0)
            break;

        if (opt_api_port == 4068 && errno == EADDRINUSE && port_probe_count < 64) {
            port++;
            port_probe_count++;
            continue;
        }

        applog(LOG_WARNING, "API bind to %s:%d failed: %s",
               bind_addr, port, strerror(errno));
        close(listen_fd);
        return -1;
    }

    g_api_bound_port = port;
    if (port != opt_api_port) {
        applog(LOG_WARNING, "API bind to port %d failed - using port %d",
               opt_api_port, port);
    }

    if (listen(listen_fd, API_BACKLOG) < 0) {
        applog(LOG_ERR, "API listen failed: %s", strerror(errno));
        close(listen_fd);
        return -1;
    }

    flags = fcntl(listen_fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);

    return listen_fd;
}

static const struct api_command *api_find_command(const char *command)
{
    for (size_t i = 0; i < sizeof(g_api_commands) / sizeof(g_api_commands[0]); i++) {
        if (strcmp(command, g_api_commands[i].name) == 0)
            return &g_api_commands[i];
    }

    return NULL;
}

static void api_handle_client(int client_fd)
{
    char request[API_RECV_SIZE + 1];
    char command[64];
    char params[256];
    const char *websocket_key = NULL;
    const struct api_command *api_command;
    char *response = NULL;
    size_t response_size;
    ssize_t received;

    received = api_recv_request(client_fd, request, sizeof(request));
    if (received <= 0)
        return;

    if (!api_parse_command(request, command, sizeof(command), params, sizeof(params), &websocket_key))
        return;

    api_command = api_find_command(command);
    if (!api_command)
        return;

    response_size = api_response_capacity(api_command);
    response = (char *)calloc(1, response_size);
    if (!response) {
        applog(LOG_ERR, "Failed to allocate API response buffer");
        return;
    }

    response[0] = '\0';
    api_command->handler(response, response_size, params);

    if (websocket_key)
        api_send_websocket_response(client_fd, response, websocket_key);
    else
        api_send_response(client_fd, response);

    free(response);
}

static void *api_thread_main(void *userdata)
{
    int listen_fd;
    (void)userdata;

    listen_fd = api_open_listen_socket();
    if (listen_fd < 0) {
        pthread_mutex_lock(&g_api_service_lock);
        g_api_thread_active = false;
        g_api_shutdown_requested = false;
        g_api_startup_complete = true;
        g_api_startup_succeeded = false;
        pthread_cond_broadcast(&g_api_service_cond);
        pthread_mutex_unlock(&g_api_service_lock);
        return NULL;
    }

    g_api_startup_time = time(NULL);
    api_reset_history();

    pthread_mutex_lock(&g_api_service_lock);
    g_api_startup_complete = true;
    g_api_startup_succeeded = true;
    pthread_cond_broadcast(&g_api_service_cond);
    pthread_mutex_unlock(&g_api_service_lock);

    if (strcmp(api_bind_address(), "127.0.0.1") == 0)
        applog(LOG_INFO, "API open locally in read-only mode on %s:%d", api_bind_address(), g_api_bound_port);
    else
        applog(LOG_INFO, "API open to the network in read-only mode on %s:%d", api_bind_address(), g_api_bound_port);

    while (!miner_should_abort() && !api_shutdown_requested()) {
        int ready;

        api_collect_history_sample(time(NULL));

        ready = api_wait_for_fd(listen_fd, false, 1000);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            applog(LOG_WARNING, "API select failed: %s", strerror(errno));
            break;
        }

        if (ready == 0)
            continue;

        while (1) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);

            if (client_fd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                if (errno == EINTR)
                    continue;
                applog(LOG_WARNING, "API accept failed: %s", strerror(errno));
                break;
            }

            api_handle_client(client_fd);
            close(client_fd);
        }
    }

    close(listen_fd);

    pthread_mutex_lock(&g_api_service_lock);
    g_api_thread_active = false;
    g_api_shutdown_requested = false;
    g_api_startup_complete = false;
    g_api_startup_succeeded = false;
    pthread_cond_broadcast(&g_api_service_cond);
    pthread_mutex_unlock(&g_api_service_lock);

    return NULL;
}

static char *build_summary_response(char *out, size_t out_size, const char *params)
{
    struct miner_api_snapshot miner_snapshot;
    struct stratum_api_pool_snapshot pool_snapshot;
    time_t now = time(NULL);
    double uptime;
    double accepted_per_minute;
    double diff = 0.0;

    (void)params;

    miner_get_api_snapshot(&miner_snapshot);
    stratum_get_api_pool_snapshot(miner_get_current_pool_index(), &pool_snapshot);

    if (pool_snapshot.work_ready)
        diff = pool_snapshot.current_work.targetdiff;

    uptime = g_api_startup_time ? difftime(now, g_api_startup_time) : 0.0;
    accepted_per_minute = uptime > 0.0
        ? (60.0 * pool_snapshot.runtime_stats.share_accepted_total) / uptime
        : 0.0;

    snprintf(out, out_size,
             "NAME=%s;VER=%s;API=%s;ALGO=%s;GPUS=%d;KHS=%.2f;SOLV=%d;ACC=%u;REJ=%u;"
             "ACCMN=%.3f;DIFF=%.6f;NETKHS=%.0f;POOLS=%d;WAIT=%u;UPTIME=%.0f;TS=%u|",
             PACKAGE_NAME, PACKAGE_VERSION, API_VERSION, algo_names[opt_algo],
             miner_snapshot.thread_count, miner_snapshot.global_hashrate / 1000.0,
             0, pool_snapshot.runtime_stats.share_accepted_total,
             pool_snapshot.runtime_stats.share_rejected_total, accepted_per_minute,
             diff, 0.0, num_pools, 0U, uptime, (unsigned int)now);

    return out;
}

static char *build_threads_response(char *out, size_t out_size, const char *params)
{
    struct miner_api_snapshot miner_snapshot;
    int cpu_temp;
    size_t pos = 0;
    bool truncated = false;

    (void)params;

    miner_get_api_snapshot(&miner_snapshot);
    cpu_temp = miner_snapshot.cpu_temp > 0 ? miner_snapshot.cpu_temp : 0;

    out[0] = '\0';
    for (int i = 0; i < miner_snapshot.thread_count; i++) {
        const struct miner_thread_api_stats *thread_stats = &miner_snapshot.threads[i];
        const char *card_name = thread_stats->cpu_is_big ? "cpu-big" : "cpu-little";

        if (!api_appendf(out, out_size, &pos,
                         "GPU=%d;BUS=%d;CARD=%s;TEMP=%.1f;POWER=%u;FAN=%u;RPM=%u;"
                         "FREQ=%u;MEMFREQ=%u;GPUF=%u;MEMF=%u;KHS=%.2f;KHW=%.5f;PLIM=%u;"
                         "ACC=%u;REJ=%u;HWF=%u;I=%.1f;THR=%u|",
                         i, thread_stats->cpu_id, card_name, (double)cpu_temp,
                         0U, 0U, 0U,
                         (unsigned int)thread_stats->cpu_max_freq_mhz, 0U,
                         (unsigned int)thread_stats->cpu_max_freq_mhz, 0U,
                         thread_stats->hashrate / 1000.0, 0.0, 0U,
                         thread_stats->accepted, thread_stats->rejected, 0U,
                         100.0, 0U)) {
            truncated = true;
            break;
        }
    }

    if (truncated)
        applog(LOG_WARNING, "API threads response truncated to %zu bytes", out_size);

    return out;
}

static char *build_pool_response(char *out, size_t out_size, const char *params)
{
    struct stratum_api_pool_snapshot snapshot;
    int pool_index = miner_get_current_pool_index();
    time_t now = time(NULL);
    uint32_t last_share = 0;
    uint32_t uptime = 0;
    char pool_label[64];
    char xnonce2_hex[2 + 64 + 1];
    const char *job_id = "";
    double diff = 0.0;
    uint32_t height = 0;

    if (params && params[0] != '\0') {
        int requested = atoi(params);
        if (requested >= 0 && requested < num_pools)
            pool_index = requested;
    }

    stratum_get_api_pool_snapshot(pool_index, &snapshot);

    if (snapshot.last_share_time)
        last_share = (uint32_t)(now - snapshot.last_share_time);
    if (g_api_startup_time)
        uptime = (uint32_t)(now - g_api_startup_time);

    if (pools[pool_index].name[0]) {
        snprintf(pool_label, sizeof(pool_label), "%s", pools[pool_index].name);
    } else if (pools[pool_index].short_url[0]) {
        snprintf(pool_label, sizeof(pool_label), "%s", pools[pool_index].short_url);
    } else {
        snprintf(pool_label, sizeof(pool_label), "%s", pools[pool_index].url);
    }

    xnonce2_hex[0] = '\0';
    if (snapshot.work_ready) {
        size_t xnonce2_len = snapshot.current_work.xnonce2_len;
        if (xnonce2_len > 0 && xnonce2_len <= 32) {
            xnonce2_hex[0] = '0';
            xnonce2_hex[1] = 'x';
            cbin2hex(xnonce2_hex + 2, (const char *)snapshot.current_work.xnonce2, xnonce2_len);
        }

        job_id = snapshot.current_work.job_id;
        diff = snapshot.current_work.targetdiff;
        height = snapshot.current_work.height;
    }

    snprintf(out, out_size,
             "POOL=%s;ALGO=%s;URL=%s;USER=%s;SOLV=%d;ACC=%u;REJ=%u;STALE=%u;H=%u;JOB=%s;DIFF=%.6f;"
             "BEST=%.6f;N2SZ=%u;N2=%s;PING=%u;DISCO=%u;WAIT=%u;UPTIME=%u;LAST=%u|",
             pool_label, algo_names[opt_algo], pools[pool_index].url, pools[pool_index].user,
             0, snapshot.accepted_count, snapshot.rejected_count, 0U, height, job_id, diff,
             snapshot.best_share, snapshot.work_ready ? (unsigned int)snapshot.current_work.xnonce2_len : 0U,
             xnonce2_hex, 0U, 0U, 0U, uptime, last_share);

    return out;
}

static char *build_history_response(char *out, size_t out_size, const char *params)
{
    int filter_thread = -1;
    size_t pos = 0;

    if (params && params[0] != '\0')
        filter_thread = atoi(params);

    out[0] = '\0';
    for (size_t offset = 0; offset < g_api_history_count; offset++) {
        size_t index = (g_api_history_head + API_HISTORY_SIZE - g_api_history_count + offset) % API_HISTORY_SIZE;
        const struct api_history_entry *entry = &g_api_history[index];

        if (filter_thread >= 0 && entry->thread_id != filter_thread)
            continue;

        if (!api_appendf(out, out_size, &pos,
                         "GPU=%d;H=%u;KHS=%.2f;DIFF=%g;COUNT=%llu;FOUND=%u;ID=%u;TS=%u|",
                         entry->thread_id, entry->height, entry->khs, entry->diff,
                         (unsigned long long)entry->hash_count, 0U,
                         entry->id, (unsigned int)entry->timestamp)) {
            break;
        }
    }

    if (pos == 0)
        snprintf(out, out_size, "|");

    return out;
}

static char *build_hwinfo_response(char *out, size_t out_size, const char *params)
{
    char os_name[128];
    int cpu_temp;

    (void)params;

    cpu_temp = get_cpu_temp();
    snprintf(out, out_size, "OS=%s;NVDRIVER=%s;CPUS=%d;CPUTEMP=%d;CPUFREQ=%d|",
             api_get_os_name(os_name, sizeof(os_name)), "",
             g_num_cpus > 0 ? g_num_cpus : opt_n_threads,
             cpu_temp > 0 ? cpu_temp : 0, api_find_max_cpu_freq_mhz());
    return out;
}

static char *build_meminfo_response(char *out, size_t out_size, const char *params)
{
    (void)params;

    snprintf(out, out_size, "STATS=%u;HASHLOG=%u;MEM=%llu|",
             (unsigned int)g_api_history_count, 0U,
             (unsigned long long)sizeof(g_api_history));
    return out;
}

static char *build_scanlog_response(char *out, size_t out_size, const char *params)
{
    (void)params;

    snprintf(out, out_size, "|");
    return out;
}

static char *build_help_response(char *out, size_t out_size, const char *params)
{
    size_t pos = 0;

    (void)params;

    out[0] = '\0';
    for (size_t i = 0; i < sizeof(g_api_commands) / sizeof(g_api_commands[0]); i++) {
        if (!api_appendf(out, out_size, &pos, "%s\n", g_api_commands[i].name))
            break;
    }

    if (pos < out_size)
        snprintf(out + pos, out_size - pos, "|");

    return out;
}

bool api_start_service(void)
{
    int rc;
    bool reap_join = false;
    bool startup_succeeded;

    if (opt_api_port <= 0)
        return true;

    pthread_mutex_lock(&g_api_service_lock);
    if (!g_api_thread_active && g_api_thread_join_pending)
        reap_join = true;
    if (g_api_thread_active) {
        pthread_mutex_unlock(&g_api_service_lock);
        return true;
    }
    pthread_mutex_unlock(&g_api_service_lock);

    if (reap_join)
        pthread_join(g_api_thread, NULL);

    pthread_mutex_lock(&g_api_service_lock);
    g_api_thread_join_pending = false;
    g_api_shutdown_requested = false;
    g_api_startup_complete = false;
    g_api_startup_succeeded = false;
    rc = pthread_create(&g_api_thread, NULL, api_thread_main, NULL);
    if (rc == 0) {
        g_api_thread_active = true;
        g_api_thread_join_pending = true;
    }
    pthread_mutex_unlock(&g_api_service_lock);

    if (rc != 0) {
        applog(LOG_WARNING, "Failed to start API thread");
        return false;
    }

    pthread_mutex_lock(&g_api_service_lock);
    while (!g_api_startup_complete)
        pthread_cond_wait(&g_api_service_cond, &g_api_service_lock);
    startup_succeeded = g_api_startup_succeeded;
    pthread_mutex_unlock(&g_api_service_lock);

    if (!startup_succeeded) {
        pthread_join(g_api_thread, NULL);
        pthread_mutex_lock(&g_api_service_lock);
        g_api_thread_join_pending = false;
        g_api_thread_active = false;
        pthread_mutex_unlock(&g_api_service_lock);
    }

    return startup_succeeded;
}

void api_stop_service(void)
{
    bool should_join = false;

    pthread_mutex_lock(&g_api_service_lock);
    if (g_api_thread_join_pending) {
        g_api_shutdown_requested = true;
        should_join = true;
    }
    pthread_mutex_unlock(&g_api_service_lock);

    if (should_join) {
        pthread_join(g_api_thread, NULL);
        pthread_mutex_lock(&g_api_service_lock);
        g_api_thread_join_pending = false;
        g_api_thread_active = false;
        g_api_shutdown_requested = false;
        pthread_mutex_unlock(&g_api_service_lock);
    }
}
