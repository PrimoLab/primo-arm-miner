#ifndef DNS_FALLBACK_H
#define DNS_FALLBACK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal self-contained DNS fallback resolver.
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
 * PRIMO_DNS_SERVERS="ip[,ip...]" (IPv4 literals, max 4) overrides the
 * resolver list — a test/field-debug hook, mirroring the proxy's injectable
 * server list.
 *
 * Matches the Go proxy's dial.go fallback policy (its Sol-reviewed shape):
 *  - ALL answer addresses are returned, not just the first — pools run
 *    round-robin DNS and the first A record may be the dead one. The caller
 *    hands the whole list to CURLOPT_RESOLVE and libcurl walks it.
 *  - A records first; AAAA is queried only when NO A record was found
 *    anywhere (v6-only pools) — IPv4 stays preferred (MinerService
 *    precedent: v6 routes are the flakier path on phones).
 *  - The ENTIRE walk (every server, both transports, both qtypes) shares
 *    one ~10 s budget, with per-exchange socket timeouts clamped to what
 *    remains, and aborts early when miner_should_abort() trips so shutdown
 *    never waits out a DNS walk.
 *
 * No external dependencies (same policy as the OpenSSL-free API handshake).
 */

#define DNS_FALLBACK_MAX_IPS    8
#define DNS_FALLBACK_ADDRSTRLEN 46   /* INET6_ADDRSTRLEN */

/* Resolve host into up to max_ips textual addresses (IPv4 dotted-quad
 * and/or bare IPv6), IPv4 first. An address literal is copied through as a
 * single entry. Returns the number of addresses (> 0) on success, -1 on
 * failure/disabled. Thread-safe, no global state. */
int dns_fallback_resolve(const char *host,
                         char ips[][DNS_FALLBACK_ADDRSTRLEN], int max_ips);

#ifdef __cplusplus
}
#endif

#endif /* DNS_FALLBACK_H */
