#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>

#include "miner.h"
#include "stratum_internal.h"

#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)
#define STRATUM_MAX_LINE_BYTES (256 * 1024)

static int stratum_poll_socket(curl_socket_t sock, short events, int timeout_ms, short *revents_out)
{
    struct pollfd pfd;
    int ready;

    if (revents_out)
        *revents_out = 0;
    if (sock == CURL_SOCKET_BAD || sock < 0)
        return -1;

    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = (int)sock;
    pfd.events = events;

    while (1) {
        ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0 && errno == EINTR)
            continue;
        if (revents_out)
            *revents_out = pfd.revents;
        return ready;
    }
}

#if LIBCURL_VERSION_NUM >= 0x070f06
static int sockopt_keepalive_cb(void *userdata, curl_socket_t fd, curlsocktype purpose)
{
    int keepalive = 1;
    int tcp_keepcnt = 3;
    int tcp_keepidle = 50;
    int tcp_keepintvl = 50;

    (void)userdata;
    (void)purpose;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)))
        return 1;
#ifdef __linux
    if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &tcp_keepcnt, sizeof(tcp_keepcnt)))
        return 1;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &tcp_keepidle, sizeof(tcp_keepidle)))
        return 1;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &tcp_keepintvl, sizeof(tcp_keepintvl)))
        return 1;
#endif

    return 0;
}
#endif

/* TLS variant of send_line: the payload must go through the TLS record
 * layer, so it is written with curl_easy_send on the CONNECT_ONLY handle
 * (non-blocking; CURLE_AGAIN -> wait for socket writability and retry).
 * Called with stratum_sock_lock held, like send_line — for TLS that lock is
 * load-bearing beyond the socket: the TLS session state is NOT full-duplex
 * thread-safe, so the receive path takes the same lock around its (equally
 * non-blocking) curl_easy_recv calls. */
static bool send_line_tls(struct stratum_ctx *sctx, const char *s)
{
    /* One heap line with the trailing newline: curl_easy_send has no iovec
     * form, and two separate sends would double the record overhead. */
    size_t len = strlen(s);
    char *line = (char *)malloc(len + 2);
    size_t sent = 0;

    if (!line)
        return false;
    memcpy(line, s, len);
    line[len] = '\n';
    line[len + 1] = '\0';

    while (sent < len + 1) {
        size_t n = 0;
        CURLcode rc;
        short revents = 0;

        if (!sctx->curl || sctx->sock == CURL_SOCKET_BAD) {
            free(line);
            return false;
        }
        rc = curl_easy_send(sctx->curl, line + sent, len + 1 - sent, &n);
        if (rc == CURLE_OK) {
            sent += n;
            continue;
        }
        if (rc != CURLE_AGAIN) {
            if (opt_debug)
                applog(LOG_DEBUG, "send_line_tls: curl_easy_send failed (%d)", (int)rc);
            free(line);
            return false;
        }
        if (stratum_poll_socket(sctx->sock, POLLOUT, 30000, &revents) <= 0 ||
            (revents & (POLLERR | POLLHUP | POLLNVAL))) {
            if (opt_debug)
                applog(LOG_DEBUG, "send_line_tls: socket not writable");
            free(line);
            return false;
        }
    }

    free(line);
    return true;
}

static bool send_line(curl_socket_t sock, const char *s)
{
    size_t len;
    size_t total_len;
    size_t sent = 0;
    static const char newline = '\n';
    int send_flags = 0;

#ifdef MSG_NOSIGNAL
    send_flags |= MSG_NOSIGNAL;
#endif

    if (!s)
        return false;
    if (sock == CURL_SOCKET_BAD) {
        if (opt_debug)
            applog(LOG_DEBUG, "send_line: invalid socket");
        return false;
    }

    len = strlen(s);
    total_len = len + 1;

    while (sent < total_len) {
        struct iovec iov[2];
        struct msghdr msg;
        int iovcnt = 0;
        ssize_t n;
        size_t payload_sent = sent < len ? sent : len;
        size_t newline_sent = sent > len ? sent - len : 0;
        short revents = 0;

        if (payload_sent < len) {
            iov[iovcnt].iov_base = (void *)(s + payload_sent);
            iov[iovcnt].iov_len = len - payload_sent;
            iovcnt++;
        }
        if (newline_sent == 0) {
            iov[iovcnt].iov_base = (void *)&newline;
            iov[iovcnt].iov_len = 1;
            iovcnt++;
        }

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = iov;
        msg.msg_iovlen = (size_t)iovcnt;

        int sel_ret = stratum_poll_socket(sock, POLLOUT, 30000, &revents);
        if (sel_ret < 0) {
            if (opt_debug)
                applog(LOG_DEBUG, "send_line: poll error, errno=%d (%s)", errno, strerror(errno));
            return false;
        }
        if (sel_ret == 0) {
            if (opt_debug)
                applog(LOG_DEBUG, "send_line: poll timeout (socket not ready)");
            return false;
        }
        if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
            int sock_error = 0;
            socklen_t err_len = sizeof(sock_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_error, &err_len);
            if (opt_debug)
                applog(LOG_DEBUG, "send_line: socket error %d (revents=0x%x)", sock_error, revents);
            return false;
        }
        if (!(revents & POLLOUT)) {
            if (opt_debug)
                applog(LOG_DEBUG, "send_line: socket not writable");
            return false;
        }

        n = sendmsg(sock, &msg, send_flags);
        if (n < 0) {
            if (opt_debug)
                applog(LOG_DEBUG, "send_line: sendmsg() failed, errno=%d (%s)", errno, strerror(errno));
            if (!socket_blocks())
                return false;
            n = 0;
        }
        sent += (size_t)n;
    }

    return true;
}

bool stratum_send_line(struct stratum_ctx *sctx, const char *s)
{
    bool ret;

    if (opt_protocol)
        applog(LOG_INFO, "> %s", s);

    pthread_mutex_lock(&stratum_sock_lock);
    if (sctx->use_tls)
        ret = send_line_tls(sctx, s);
    else
        ret = send_line(sctx->sock, s);
    pthread_mutex_unlock(&stratum_sock_lock);

    return ret;
}

bool stratum_socket_full(curl_socket_t sock, int timeout)
{
    short revents = 0;
    int ready = stratum_poll_socket(sock, POLLIN, timeout * 1000, &revents);

    if (ready <= 0)
        return false;

    return (revents & (POLLIN | POLLHUP | POLLERR)) != 0;
}

static bool stratum_reserve_socket_buffer(struct stratum_ctx *sctx, size_t min_size)
{
    size_t new_size;
    char *new_buf;

    if (min_size > (STRATUM_MAX_LINE_BYTES + 1u)) {
        applog(LOG_ERR,
               "Stratum line exceeds %u bytes, dropping connection",
               (unsigned int)STRATUM_MAX_LINE_BYTES);
        return false;
    }

    if (min_size < sctx->sockbuf_size)
        return true;

    new_size = min_size + (RBUFSIZE - (min_size % RBUFSIZE));
    new_buf = (char *)realloc(sctx->sockbuf, new_size);
    if (!new_buf)
        return false;

    sctx->sockbuf = new_buf;
    sctx->sockbuf_size = new_size;
    return true;
}

/* Append exactly `incoming` received bytes to the accumulating socket buffer.
 * The caller passes the byte count from recv() rather than relying on strlen():
 * the buffer is line-delimited JSON text, and using the explicit length keeps
 * the size math correct regardless of content. The sockbuf C-string invariant
 * (no interior NUL) is enforced by the embedded-NUL check at the call site, so
 * the strlen() below always measures the true buffered length. */
static bool stratum_buffer_append(struct stratum_ctx *sctx, const char *s, size_t incoming)
{
    size_t old = strlen(sctx->sockbuf);
    size_t needed = old + incoming + 1;

    if (!stratum_reserve_socket_buffer(sctx, needed))
        return false;

    memcpy(sctx->sockbuf + old, s, incoming);
    sctx->sockbuf[old + incoming] = '\0';
    return true;
}

static bool stratum_ensure_socket_buffer(struct stratum_ctx *sctx)
{
    if (!sctx->sockbuf) {
        sctx->sockbuf = (char *)calloc(RBUFSIZE, 1);
        if (!sctx->sockbuf)
            return false;
        sctx->sockbuf_size = RBUFSIZE;
    }

    sctx->sockbuf[0] = '\0';
    return true;
}

static void stratum_reset_socket_buffer(struct stratum_ctx *sctx)
{
    if (sctx->sockbuf)
        sctx->sockbuf[0] = '\0';
}

static char *stratum_take_buffer_line(struct stratum_ctx *sctx)
{
    char *newline;
    char *line;
    size_t line_len;
    size_t remaining;

    newline = strchr(sctx->sockbuf, '\n');
    if (!newline)
        return NULL;

    line_len = (size_t)(newline - sctx->sockbuf);
    line = (char *)malloc(line_len + 1);
    if (!line)
        return NULL;

    memcpy(line, sctx->sockbuf, line_len);
    line[line_len] = '\0';

    remaining = strlen(newline + 1);
    memmove(sctx->sockbuf, newline + 1, remaining + 1);
    return line;
}

char *stratum_recv_line_timeout(struct stratum_ctx *sctx, int timeout, bool *timed_out, bool log_timeout)
{
    char *sret = NULL;
    time_t deadline = 0;

    if (timed_out)
        *timed_out = false;
    if (!sctx->sockbuf)
        return NULL;
    if (timeout < 1)
        timeout = 1;
    deadline = time(NULL) + timeout;

    if (!strchr(sctx->sockbuf, '\n')) {
        bool ret = true;
        while (!strchr(sctx->sockbuf, '\n')) {
            char s[RBUFSIZE];
            ssize_t n;
            int remaining = (int)difftime(deadline, time(NULL));

            if (remaining < 1) {
                if (log_timeout)
                    applog(LOG_ERR, "stratum_recv_line timed out");
                if (timed_out)
                    *timed_out = true;
                goto out;
            }

            memset(s, 0, RBUFSIZE);
            if (sctx->use_tls) {
                /* TLS order is inverted vs the raw path: try curl_easy_recv
                 * FIRST (decrypted bytes can be buffered in the TLS layer
                 * with nothing pending on the socket — polling first would
                 * deadlock on them), and only wait for socket readability on
                 * CURLE_AGAIN. The call itself never blocks (CONNECT_ONLY
                 * sockets are non-blocking) and runs under stratum_sock_lock
                 * because TLS session state, unlike a raw socket, is not
                 * safe for concurrent send/recv from two threads. */
                size_t nread = 0;
                CURLcode rc;

                pthread_mutex_lock(&stratum_sock_lock);
                if (!sctx->curl || sctx->sock == CURL_SOCKET_BAD)
                    rc = CURLE_RECV_ERROR;
                else
                    rc = curl_easy_recv(sctx->curl, s, RECVSIZE, &nread);
                pthread_mutex_unlock(&stratum_sock_lock);

                if (rc == CURLE_AGAIN) {
                    if (!stratum_socket_full(sctx->sock, remaining)) {
                        if (log_timeout)
                            applog(LOG_ERR, "stratum_recv_line timed out");
                        if (timed_out)
                            *timed_out = true;
                        goto out;
                    }
                    continue;
                }
                if (rc != CURLE_OK || nread == 0) {
                    /* nread == 0 with CURLE_OK is the TLS-layer EOF. */
                    ret = false;
                    break;
                }
                n = (ssize_t)nread;
            } else {
                if (!stratum_socket_full(sctx->sock, remaining)) {
                    if (log_timeout)
                        applog(LOG_ERR, "stratum_recv_line timed out");
                    if (timed_out)
                        *timed_out = true;
                    goto out;
                }

                n = recv(sctx->sock, s, RECVSIZE, 0);
                if (!n) {
                    ret = false;
                    break;
                }
                if (n < 0) {
                    if (!socket_blocks()) {
                        ret = false;
                        break;
                    }
                    continue;
                }
            }
            {
                /* Stratum is line-delimited JSON text. An embedded NUL is not
                 * valid in that stream and would corrupt the C-string buffer
                 * (silently dropping everything after it); treat it as a fatal
                 * protocol error rather than truncating the data. */
                if (memchr(s, '\0', (size_t)n)) {
                    applog(LOG_ERR, "Stratum stream contains an embedded NUL byte, dropping connection");
                    ret = false;
                    break;
                }
                if (!stratum_buffer_append(sctx, s, (size_t)n)) {
                    applog(LOG_ERR, "Failed to grow stratum socket buffer");
                    ret = false;
                    break;
                }
            }
        }

        if (!ret) {
            if (opt_debug)
                applog(LOG_DEBUG, "stratum_recv_line failed");
            goto out;
        }
        if (!strchr(sctx->sockbuf, '\n')) {
            if (log_timeout)
                applog(LOG_ERR, "stratum_recv_line timed out");
            if (timed_out)
                *timed_out = true;
            goto out;
        }
    }

    sret = stratum_take_buffer_line(sctx);
    if (!sret) {
        applog(LOG_ERR, "stratum_recv_line failed to parse a newline-terminated string");
        goto out;
    }

out:
    if (sret && opt_protocol)
        applog(LOG_INFO, "< %s", sret);
    return sret;
}

#if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose, struct curl_sockaddr *addr)
{
    curl_socket_t *sock = (curl_socket_t *)clientp;
    (void)purpose;
    *sock = socket(addr->family, addr->socktype, addr->protocol);
    return *sock;
}
#endif

static bool stratum_prepare_transport_locked(struct stratum_ctx *sctx, CURL **curl_out)
{
    if (sctx->curl)
        curl_easy_cleanup(sctx->curl);
    sctx->curl = curl_easy_init();
    if (!sctx->curl) {
        applog(LOG_ERR, "CURL initialization failed");
        return false;
    }
    if (!stratum_ensure_socket_buffer(sctx)) {
        applog(LOG_ERR, "Failed to allocate stratum socket buffer");
        curl_easy_cleanup(sctx->curl);
        sctx->curl = NULL;
        return false;
    }

    *curl_out = sctx->curl;
    return true;
}

/* TLS is selected by URL scheme: stratum+ssl:// (xmrig convention) plus the
 * stratum+tcps:// (cpuminer), ssl:// and tls:// aliases. Everything else is
 * plain TCP, exactly as before. */
static bool stratum_url_is_tls(const char *url)
{
    return strncasecmp(url, "stratum+ssl://", 14) == 0 ||
           strncasecmp(url, "stratum+tcps://", 15) == 0 ||
           strncasecmp(url, "ssl://", 6) == 0 ||
           strncasecmp(url, "tls://", 6) == 0;
}

static bool stratum_build_curl_url(struct stratum_ctx *sctx)
{
    const char *scheme;
    char *curl_url;
    size_t buf_len;

    if (!sctx->url)
        return false;

    scheme = strstr(sctx->url, "://");
    if (!scheme)
        return false;

    sctx->use_tls = stratum_url_is_tls(sctx->url) ? 1 : 0;

    buf_len = strlen(sctx->url) + 6;
    curl_url = (char *)malloc(buf_len);
    if (!curl_url)
        return false;

    /* https:// + CURLOPT_CONNECT_ONLY makes libcurl run the TLS handshake
     * during curl_easy_perform and route curl_easy_send/recv through the
     * TLS record layer — TLS support without linking any TLS library
     * ourselves (the 2026-06-10 OpenSSL removal stands; the SONAME problem
     * is libcurl's). */
    snprintf(curl_url, buf_len, sctx->use_tls ? "https%s" : "http%s", scheme);
    free(sctx->curl_url);
    sctx->curl_url = curl_url;
    return true;
}

static void stratum_log_connect_failure(struct stratum_ctx *sctx, CURLcode rc)
{
    const char *fallback = curl_easy_strerror(rc);
    const char *detail = sctx->curl_err_str[0] ? sctx->curl_err_str : fallback;

    if (strcmp(detail, fallback) != 0)
        applog(LOG_ERR, "Stratum connection failed to %s: %s (%s)", sctx->url, detail, fallback);
    else
        applog(LOG_ERR, "Stratum connection failed to %s: %s", sctx->url, detail);

    switch (rc) {
    case CURLE_COULDNT_RESOLVE_HOST:
        applog(LOG_ERR, "Connect detail: DNS resolution failed for the pool host");
        break;
    case CURLE_COULDNT_RESOLVE_PROXY:
        applog(LOG_ERR, "Connect detail: proxy host resolution failed");
        break;
    case CURLE_COULDNT_CONNECT:
        applog(LOG_ERR, "Connect detail: host resolved but TCP connect to the pool failed");
        break;
    case CURLE_OPERATION_TIMEDOUT:
        applog(LOG_ERR, "Connect detail: the pool connect attempt timed out");
        break;
    default:
        break;
    }
}

static void stratum_close_transport_locked(struct stratum_ctx *sctx)
{
    if (sctx->curl) {
        curl_easy_cleanup(sctx->curl);
        sctx->curl = NULL;
    }
    sctx->sock = CURL_SOCKET_BAD;
    stratum_reset_socket_buffer(sctx);
}

void stratum_close_transport(struct stratum_ctx *sctx)
{
    pthread_mutex_lock(&stratum_sock_lock);
    stratum_close_transport_locked(sctx);
    pthread_mutex_unlock(&stratum_sock_lock);
}

bool stratum_connect(struct stratum_ctx *sctx)
{
    CURL *curl;
    int rc;

    if (!sctx->url || !sctx->url[0]) {
        applog(LOG_ERR, "No stratum URL configured");
        return false;
    }

    pthread_mutex_lock(&stratum_sock_lock);
    if (!stratum_prepare_transport_locked(sctx, &curl)) {
        pthread_mutex_unlock(&stratum_sock_lock);
        return false;
    }
    pthread_mutex_unlock(&stratum_sock_lock);

    if (!stratum_build_curl_url(sctx)) {
        applog(LOG_ERR, "Failed to build CURL URL for %s", sctx->url);
        stratum_close_transport(sctx);
        return false;
    }

    if (sctx->use_tls) {
        const curl_version_info_data *ci = curl_version_info(CURLVERSION_NOW);
        if (!ci || !(ci->features & CURL_VERSION_SSL)) {
            applog(LOG_ERR,
                   "stratum+ssl requested but TLS is not supported by this libcurl build "
                   "(%s) — use stratum+tcp or a TLS-enabled libcurl",
                   ci && ci->version ? ci->version : "unknown");
            stratum_close_transport(sctx);
            return false;
        }
    }

    if (opt_protocol)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    sctx->curl_err_str[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_URL, sctx->curl_url);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, miner_get_pool_timeout(sctx->pooln));
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sctx->curl_err_str);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
    // Proxy configuration is not exposed by this miner; disable implicit env proxies.
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    if (sctx->use_tls) {
        /* Pool TLS certificates are almost universally self-signed, and the
         * ecosystem norm (xmrig included) is not to verify them — TLS here
         * protects against passive snooping of wallet/worker credentials,
         * not active MITM. Verification also breaks the Android/JVM-resolved
         * connect-by-IP flow (no SNI/hostname to match). */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
#if LIBCURL_VERSION_NUM >= 0x070f06
    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_grab_cb);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sctx->sock);
#endif
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);

    rc = curl_easy_perform(curl);
    if (rc) {
        stratum_log_connect_failure(sctx, (CURLcode)rc);
        stratum_close_transport(sctx);
        return false;
    }

#if LIBCURL_VERSION_NUM < 0x071101
    curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, (long *)&sctx->sock);
#endif

    return true;
}

void stratum_request_shutdown(struct stratum_ctx *sctx)
{
    pthread_mutex_lock(&stratum_sock_lock);
    if (sctx->sock != CURL_SOCKET_BAD)
        shutdown(sctx->sock, SHUT_RDWR);
    pthread_mutex_unlock(&stratum_sock_lock);
}
