#ifndef PRIMO_SCHED_COMPAT_H
#define PRIMO_SCHED_COMPAT_H

/*
 * CPU-affinity shim for non-Linux hosts (e.g. macOS dev builds).
 *
 * The miner's affinity/topology code targets Linux's sched_setaffinity(2)
 * family, which macOS doesn't expose (Apple's scheduler has no equivalent
 * pinning API). These stubs let that code compile unchanged elsewhere;
 * every caller already treats a failed pin/query as "run unpinned" (Android
 * cpuset denial does the same today), so returning "unsupported" here is a
 * correctness-preserving no-op, not a behavior change in disguise.
 */
#if !defined(__linux__)

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPU_SETSIZE 1024

typedef struct {
    unsigned long __bits[CPU_SETSIZE / (8 * sizeof(unsigned long))];
} cpu_set_t;

static inline void CPU_ZERO(cpu_set_t *set) {
    for (size_t i = 0; i < sizeof(set->__bits) / sizeof(set->__bits[0]); i++)
        set->__bits[i] = 0;
}

static inline void CPU_SET(int cpu, cpu_set_t *set) {
    if (cpu < 0 || cpu >= CPU_SETSIZE) return;
    set->__bits[cpu / (8 * sizeof(unsigned long))] |=
        1UL << (cpu % (8 * sizeof(unsigned long)));
}

static inline int CPU_ISSET(int cpu, const cpu_set_t *set) {
    if (cpu < 0 || cpu >= CPU_SETSIZE) return 0;
    return (set->__bits[cpu / (8 * sizeof(unsigned long))] >>
            (cpu % (8 * sizeof(unsigned long)))) & 1UL;
}

static inline int CPU_COUNT(const cpu_set_t *set) {
    int n = 0;
    for (size_t i = 0; i < sizeof(set->__bits) / sizeof(set->__bits[0]); i++) {
        unsigned long w = set->__bits[i];
        while (w) { n += (int)(w & 1UL); w >>= 1; }
    }
    return n;
}

static inline void CPU_AND(cpu_set_t *dst, const cpu_set_t *a, const cpu_set_t *b) {
    for (size_t i = 0; i < sizeof(dst->__bits) / sizeof(dst->__bits[0]); i++)
        dst->__bits[i] = a->__bits[i] & b->__bits[i];
}

/* Always report "no such API" — callers fall back to unpinned operation. */
static inline int sched_getaffinity(int pid, size_t cpusetsize, cpu_set_t *set) {
    (void)pid; (void)cpusetsize; (void)set;
    return -1;
}

static inline int sched_setaffinity(int pid, size_t cpusetsize, const cpu_set_t *set) {
    (void)pid; (void)cpusetsize; (void)set;
    return -1;
}

static inline int sched_getcpu(void) {
    return -1;
}

#ifdef __cplusplus
}
#endif

#endif /* !__linux__ */

#endif /* PRIMO_SCHED_COMPAT_H */