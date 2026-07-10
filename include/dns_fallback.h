#ifndef DNS_FALLBACK_H
#define DNS_FALLBACK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal self-contained DNS fallback resolver (A records only, IPv4).
 *
 * Used ONLY when the platform resolver fails (CURLE_COULDNT_RESOLVE_HOST):
 *  - Android APK subprocess: the app sandbox blocks getaddrinfo for a raw
 *    exec'd native process (bionic's resolver needs the app's netd context),
 *    even though plain TCP/UDP sockets work. MinerService pre-resolves the
 *    USER pools JVM-side, but the compiled-in dev-fee pool hostnames and
 *    pool-directed client.reconnect targets have no JVM to lean on.
 *  - CLI with a filtering resolver: some public resolvers (observed: Quad9)
 *    NXDOMAIN mining-pool hostnames wholesale.
 *
 * Queries go straight to public resolvers (Cloudflare 1.1.1.1, then Google
 * 8.8.8.8 — both non-filtering) over UDP:53 with a TCP:53 retry on
 * truncation. This bypasses the system resolver ON FAILURE ONLY; the
 * platform resolver (with the user's VPN/private-DNS setup) is always tried
 * first via libcurl. Set PRIMO_DNS_FALLBACK=0 to disable entirely.
 *
 * No external dependencies (same policy as the OpenSSL-free API handshake).
 */

/* Resolve host to a dotted-quad IPv4 string in ip_out (needs >= 16 bytes).
 * A host that is already an IPv4 literal is copied through. Returns 0 on
 * success, -1 on failure/disabled. Thread-safe, no global state. */
int dns_fallback_resolve_ipv4(const char *host, char *ip_out, size_t ip_out_len);

#ifdef __cplusplus
}
#endif

#endif /* DNS_FALLBACK_H */
