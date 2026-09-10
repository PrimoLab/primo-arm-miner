#include "cpu_features.h"

#ifdef __linux__
#include <sys/auxv.h>
#include <asm/hwcap.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global CPU capabilities
cpu_capabilities_t g_cpu_caps = {0};

#if defined(__APPLE__)
static bool apple_sysctl_bool(const char *name) {
    int32_t value = 0;
    size_t size = sizeof(value);
    if (sysctlbyname(name, &value, &size, NULL, 0) != 0)
        return false;
    return value != 0;
}
#endif

cpu_capabilities_t detect_cpu_features(void) {
    cpu_capabilities_t caps = {0};

#ifdef __linux__
    // Get hardware capabilities from auxiliary vector
    unsigned long hwcap = getauxval(AT_HWCAP);

    // Check for ARMv8 crypto extensions
    caps.has_aes = !!(hwcap & HWCAP_AES);
    caps.has_pmull = !!(hwcap & HWCAP_PMULL);
    caps.has_asimd = !!(hwcap & HWCAP_ASIMD);

    // Both AES and PMULL required for full crypto support
    caps.has_armv8_crypto = caps.has_aes && caps.has_pmull && caps.has_asimd;

#elif defined(__APPLE__)
    // macOS has no getauxval/HWCAP; query the equivalent sysctl feature
    // flags instead (present on every Apple Silicon Mac — all ship with
    // mandatory ARMv8 crypto extensions, but query rather than assume so a
    // future/exotic target that lacks them is still handled correctly).
    caps.has_aes = apple_sysctl_bool("hw.optional.arm.FEAT_AES");
    caps.has_pmull = apple_sysctl_bool("hw.optional.arm.FEAT_PMULL");
    caps.has_asimd = apple_sysctl_bool("hw.optional.neon");

    caps.has_armv8_crypto = caps.has_aes && caps.has_pmull && caps.has_asimd;

#else
    // For other non-Linux systems, assume no crypto support for safety
    caps.has_aes = false;
    caps.has_pmull = false;
    caps.has_asimd = false;
    caps.has_armv8_crypto = false;
#endif

    return caps;
}

bool has_armv8_crypto_support(void) {
    return g_cpu_caps.has_armv8_crypto;
}

void init_cpu_features(void) {
    g_cpu_caps = detect_cpu_features();

    // Debug output for development
    #ifdef DEBUG
    printf("CPU Features detected:\n");
    printf("  AES: %s\n", g_cpu_caps.has_aes ? "YES" : "NO");
    printf("  PMULL: %s\n", g_cpu_caps.has_pmull ? "YES" : "NO");
    printf("  ASIMD: %s\n", g_cpu_caps.has_asimd ? "YES" : "NO");
    printf("  ARMv8 Crypto: %s\n", g_cpu_caps.has_armv8_crypto ? "YES" : "NO");
    #endif
}

/*============================================================================
 * Core Topology Detection
 *============================================================================*/

cpu_core_info_t g_cpu_cores[MAX_CPUS];
int g_num_cpus = 0;
int g_num_big_cores = 0;
int g_num_little_cores = 0;
int g_core_order[MAX_CPUS];
int g_core_order_count = 0;

/* NOTE: when adding a new ARM (0x41) big-core part here, also consider
 * verus_use_fused_for_current_cpu() in verus.cpp — its fused-dispatch
 * allowlist tracks the ARM A75+ subset of this list. */
static bool is_big_core(int implementer, int part_number) {
    switch (implementer) {
    case 0x41: /* ARM Limited */
        switch (part_number) {
        case 0xD0A: /* Cortex-A75  */
        case 0xD0B: /* Cortex-A76  */
        case 0xD0D: /* Cortex-A77  */
        case 0xD41: /* Cortex-A78  */
        case 0xD4B: /* Cortex-A78C */
        case 0xD44: /* Cortex-X1   */
        case 0xD4C: /* Cortex-X1C  */
        case 0xD47: /* Cortex-A710 */
        case 0xD48: /* Cortex-X2   */
        case 0xD4D: /* Cortex-A715 */
        case 0xD4E: /* Cortex-X3   */
        case 0xD81: /* Cortex-A720 */
        case 0xD87: /* Cortex-A725 */
        case 0xD85: /* Cortex-X925 (a.k.a. Cortex-X5) */
        case 0xD8B: /* C1-Pro     (ARM 2025 "Lumex"/C1 rebrand) */
        case 0xD8C: /* C1-Ultra   */
        case 0xD90: /* C1-Premium */
        case 0xD82: /* Cortex-X4 — was previously (wrongly) listed as 0xD84.
                     * 0xD84 is Neoverse-V3 (server, never in phones); the real
                     * Cortex-X4 prime in SD8Gen3 / Dimensity 9300 / Exynos 2400
                     * / Tensor G4 is 0xD82, so it was being misdetected as
                     * LITTLE and ran the x1 CLHash path. Per util-linux
                     * lscpu-arm + Linux cputype.h. */
            return true;
        default:
            return false;
        }
    case 0x51: /* Qualcomm — Kryo part numbers (per util-linux lscpu-arm).
                * Only the Gold/Prime (big) tiers belong here. The Silver tiers
                * 0x803 (Kryo 3XX) and 0x805 (Kryo 4XX/5XX) are A55-class LITTLE
                * cores — listing them as big inverted cluster detection on
                * SDM845 (Gold=0x802 was missing → A75 ran the x1 CLHash path). */
        switch (part_number) {
        case 0x001: /* Oryon (Snapdragon 8 Elite, 2024+) — custom perf core.
                     * Marked big so it gets the x2 CLHash path, but like the
                     * Samsung Mongoose it is deliberately kept OFF the Verus
                     * fused-dispatch allowlist (custom wide front-end; the fused
                     * jump table regressed -24% on the custom M4 — test before
                     * enabling). */
        case 0x802: /* Kryo 3XX Gold   (SDM845, Cortex-A75 class) */
        case 0x804: /* Kryo 4XX/5XX Gold/Prime (SD855/865, A76/A77 class) */
            return true;
        default: /* 0x800/0x801 Falkor/Kryo-v2, 0x803/0x805 Silver → LITTLE */
            return false;
        }
    case 0x53: /* Samsung — Exynos M-series */
        switch (part_number) {
        case 0x001: /* Exynos M1 */
        case 0x002: /* Exynos M2 */
        case 0x003: /* Exynos M3 */
        case 0x004: /* Exynos M4 (9820) */
        case 0x005: /* Exynos M5 */
            return true;
        default:
            return false;
        }
    default:
        return false;
    }
}

/* Fallback MIDR source for Android/Termux, where the sysfs
 * regs/identification/midr_el1 node is frequently absent or unreadable while
 * /proc/cpuinfo is not. Extracts the implementer and part for one logical CPU
 * by walking the per-processor blocks. Only called when the sysfs read fails,
 * so it does not need to be fast. */
static bool read_cpuinfo_midr(int cpu, int *implementer_out, int *part_out) {
#ifdef __linux__
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f)
        return false;

    char line[256];
    int cur = -1;
    int implementer = -1;
    int part = -1;
    bool found = false;

    while (fgets(line, sizeof(line), f)) {
        int proc_id;
        unsigned int hex;

        if (sscanf(line, "processor : %d", &proc_id) == 1) {
            /* New block. If we just finished our target block, we're done. */
            if (cur == cpu && implementer >= 0 && part >= 0) {
                found = true;
                break;
            }
            cur = proc_id;
            if (cur != cpu) {
                implementer = -1;
                part = -1;
            }
        } else if (cur == cpu) {
            if (sscanf(line, "CPU implementer : %x", &hex) == 1)
                implementer = (int)hex;
            else if (sscanf(line, "CPU part : %x", &hex) == 1)
                part = (int)hex;
        }
    }
    fclose(f);

    if (!found && cur == cpu && implementer >= 0 && part >= 0)
        found = true;

    if (found) {
        if (implementer_out) *implementer_out = implementer;
        if (part_out) *part_out = part;
        return true;
    }
#endif
    (void)cpu;
    (void)implementer_out;
    (void)part_out;
    return false;
}

/* Kernel's online-CPU mask as a string (e.g. "0-3,6-7"), captured at every
 * (re)detection. Android hotplugs/parks cores, so the online set at miner
 * startup is just a snapshot — comparing against the current mask tells the
 * caller when a re-detect is worthwhile. */
static char g_online_mask_snapshot[128];

static void read_online_cpu_mask(char *buf, size_t buf_len) {
    buf[0] = '\0';
#ifdef __linux__
    FILE *f = fopen("/sys/devices/system/cpu/online", "r");
    if (!f)
        return;
    if (fgets(buf, (int)buf_len, f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            buf[--len] = '\0';
    } else {
        buf[0] = '\0';
    }
    fclose(f);
#else
    (void)buf_len;
#endif
}

bool cpu_topology_online_changed(void) {
    char current[sizeof(g_online_mask_snapshot)];
    read_online_cpu_mask(current, sizeof(current));
    /* Unreadable mask (both empty) compares equal — never forces refreshes. */
    return strcmp(current, g_online_mask_snapshot) != 0;
}

static void detect_cpu_topology_now(void) {
#ifdef __linux__
    read_online_cpu_mask(g_online_mask_snapshot, sizeof(g_online_mask_snapshot));

    g_num_cpus = 0;
    g_num_big_cores = 0;
    g_num_little_cores = 0;

    for (int cpu = 0; cpu < MAX_CPUS; cpu++) {
        char path[256];
        FILE *f;

        // Check if CPU exists
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/online", cpu);
        f = fopen(path, "r");
        if (!f) {
            // cpu0 often has no 'online' file but exists
            if (cpu > 0) {
                // Try MIDR as existence check
                snprintf(path, sizeof(path),
                         "/sys/devices/system/cpu/cpu%d/regs/identification/midr_el1", cpu);
                f = fopen(path, "r");
                if (!f) break;
                fclose(f);
            }
        } else {
            int online = 0;
            if (fscanf(f, "%d", &online) == 1 && !online) {
                fclose(f);
                continue; // CPU offline
            }
            fclose(f);
        }

        cpu_core_info_t *core = &g_cpu_cores[g_num_cpus];
        core->cpu_id = cpu;
        core->implementer = 0;
        core->part_number = 0;
        core->is_big = false;
        core->max_freq_khz = 0;

        // Read MIDR_EL1 for implementer and part number. Prefer the sysfs
        // register node; fall back to /proc/cpuinfo, which is far more reliably
        // readable on stock Android / Termux where the sysfs node is absent.
        int implementer = -1;
        int part = -1;
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/regs/identification/midr_el1", cpu);
        f = fopen(path, "r");
        if (f) {
            unsigned long long midr = 0;
            if (fscanf(f, "%llx", &midr) == 1 && midr != 0) {
                implementer = (int)((midr >> 24) & 0xFF);
                part        = (int)((midr >>  4) & 0xFFF);
            }
            fclose(f);
        }
        if (implementer < 0)
            read_cpuinfo_midr(cpu, &implementer, &part);
        if (implementer >= 0) {
            core->implementer = implementer;
            core->part_number = part;
            core->is_big      = is_big_core(implementer, part);
        }

        // Read max frequency
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", cpu);
        f = fopen(path, "r");
        if (f) {
            fscanf(f, "%d", &core->max_freq_khz);
            fclose(f);
        }

        if (core->is_big)
            g_num_big_cores++;
        else
            g_num_little_cores++;

        g_num_cpus++;
    }

    // Frequency-based fallback: if MIDR was unreadable or all part numbers were
    // unrecognised, classify by frequency. Cores above the median max-frequency
    // are big; at-or-below are LITTLE. Works for standard big.LITTLE layouts
    // (tested: SD855, Exynos 9820, RK3588).
    if (g_num_big_cores == 0 && g_num_cpus > 1) {
        int freqs[MAX_CPUS];
        for (int i = 0; i < g_num_cpus; i++)
            freqs[i] = g_cpu_cores[i].max_freq_khz;
        // Sort descending (simple insertion sort — at most 16 elements)
        for (int i = 1; i < g_num_cpus; i++) {
            int key = freqs[i];
            int j = i - 1;
            while (j >= 0 && freqs[j] < key) { freqs[j+1] = freqs[j]; j--; }
            freqs[j+1] = key;
        }
        int median_freq = freqs[g_num_cpus / 2];
        if (median_freq > 0) {
            for (int i = 0; i < g_num_cpus; i++) {
                if (g_cpu_cores[i].max_freq_khz > median_freq) {
                    g_cpu_cores[i].is_big = true;
                    g_num_big_cores++;
                    g_num_little_cores--;
                }
            }
        }
    }

    // Secondary heuristic: catch an UNRECOGNISED big core that slipped past the
    // MIDR allowlist while OTHER cores in the same SoC WERE recognised as big.
    // In that partial-recognition case the primary fallback above never fires
    // (g_num_big_cores != 0), so a prime core whose part number post-dates this
    // build would be left misclassified as LITTLE and lose the x2 path — exactly
    // how the Cortex-X4 (0xD82) and Kryo Gold (0x802) misses behaved. A core
    // clocked at or above the SLOWEST recognised big core is big-class: LITTLE
    // cores always clock below the big cluster in real big.LITTLE designs, so
    // this never promotes an A55/A510/A520. Skipped if any big core has an
    // unreadable max frequency (floor would be meaningless).
    if (g_num_big_cores > 0 && g_num_big_cores < g_num_cpus) {
        int min_big_freq = 0;
        bool big_freqs_ok = true;
        for (int i = 0; i < g_num_cpus; i++) {
            if (!g_cpu_cores[i].is_big) continue;
            int khz = g_cpu_cores[i].max_freq_khz;
            if (khz <= 0) { big_freqs_ok = false; break; }
            if (min_big_freq == 0 || khz < min_big_freq) min_big_freq = khz;
        }
        if (big_freqs_ok && min_big_freq > 0) {
            for (int i = 0; i < g_num_cpus; i++) {
                if (g_cpu_cores[i].is_big) continue;
                if (g_cpu_cores[i].max_freq_khz >= min_big_freq) {
                    g_cpu_cores[i].is_big = true;
                    g_num_big_cores++;
                    g_num_little_cores--;
                }
            }
        }
    }

    // Build sorted order: big cores first (highest freq first), then little cores
    g_core_order_count = 0;

    // First pass: big cores sorted by frequency descending
    for (int pass = 0; pass < g_num_cpus; pass++) {
        int best = -1;
        int best_freq = -1;
        for (int i = 0; i < g_num_cpus; i++) {
            if (!g_cpu_cores[i].is_big) continue;
            // Check if already in order list
            bool already = false;
            for (int j = 0; j < g_core_order_count; j++) {
                if (g_core_order[j] == g_cpu_cores[i].cpu_id) {
                    already = true;
                    break;
                }
            }
            if (already) continue;
            if (g_cpu_cores[i].max_freq_khz > best_freq) {
                best_freq = g_cpu_cores[i].max_freq_khz;
                best = i;
            }
        }
        if (best < 0) break;
        g_core_order[g_core_order_count++] = g_cpu_cores[best].cpu_id;
    }

    // Second pass: little cores sorted by frequency descending
    for (int pass = 0; pass < g_num_cpus; pass++) {
        int best = -1;
        int best_freq = -1;
        for (int i = 0; i < g_num_cpus; i++) {
            if (g_cpu_cores[i].is_big) continue;
            bool already = false;
            for (int j = 0; j < g_core_order_count; j++) {
                if (g_core_order[j] == g_cpu_cores[i].cpu_id) {
                    already = true;
                    break;
                }
            }
            if (already) continue;
            if (g_cpu_cores[i].max_freq_khz > best_freq) {
                best_freq = g_cpu_cores[i].max_freq_khz;
                best = i;
            }
        }
        if (best < 0) break;
        g_core_order[g_core_order_count++] = g_cpu_cores[best].cpu_id;
    }
#endif
}

void detect_cpu_topology(void) {
    /* Idempotent one-shot for the startup paths (benchmark and mining entry
     * points both call it). Main-thread-only at startup, so a plain static
     * flag is sufficient. Later hotplug changes are handled by explicit
     * cpu_topology_refresh() calls, which the caller must serialize. */
    static bool g_topology_detected = false;
    if (g_topology_detected)
        return;
    g_topology_detected = true;
    detect_cpu_topology_now();
}

void cpu_topology_refresh(void) {
    detect_cpu_topology_now();
}

int get_cpu_for_thread(int thr_id) {
    if (g_core_order_count == 0)
        return thr_id; // No topology info, use thread ID as CPU ID
    return g_core_order[thr_id % g_core_order_count];
}

/* Current operating frequency of a logical CPU, in kHz, or -1 if unreadable.
 * Used by the big-core frequency-cap diagnostic to tell a correctly-pinned but
 * Android-throttled (uclamp/cpuset) core from a genuinely fast one. */
int get_cpu_cur_freq_khz(int cpu_id) {
#ifdef __linux__
    char path[128];
    snprintf(path, sizeof(path),
             "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu_id);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int khz = -1;
    if (fscanf(f, "%d", &khz) != 1)
        khz = -1;
    fclose(f);
    return khz;
#else
    (void)cpu_id;
    return -1;
#endif
}

/* Human-readable core name for log hints. Implementer-aware: part numbers DO
 * collide across implementers (e.g. 0x001 is Qualcomm Oryon but also Samsung
 * Exynos-M1), so both fields are needed. Names per util-linux lscpu-arm. Unknown
 * parts fall back to a generic per-vendor label rather than a raw number. */
const char *cpu_part_name(int implementer, int part_number) {
    switch (implementer) {
    case 0x41: /* ARM */
        switch (part_number) {
        /* LITTLE / efficiency */
        case 0xD03: return "Cortex-A53";
        case 0xD04: return "Cortex-A35";
        case 0xD05: return "Cortex-A55";
        case 0xD46: return "Cortex-A510";
        case 0xD80: return "Cortex-A520";
        case 0xD8A: return "C1-Nano";
        case 0xD8F: return "Cortex-A320";
        /* performance */
        case 0xD07: return "Cortex-A57";
        case 0xD08: return "Cortex-A72";
        case 0xD09: return "Cortex-A73";
        case 0xD0A: return "Cortex-A75";
        case 0xD0B: return "Cortex-A76";
        case 0xD0D: return "Cortex-A77";
        case 0xD41: return "Cortex-A78";
        case 0xD4B: return "Cortex-A78C";
        case 0xD44: return "Cortex-X1";
        case 0xD4C: return "Cortex-X1C";
        case 0xD47: return "Cortex-A710";
        case 0xD48: return "Cortex-X2";
        case 0xD4D: return "Cortex-A715";
        case 0xD4E: return "Cortex-X3";
        case 0xD81: return "Cortex-A720";
        case 0xD82: return "Cortex-X4";
        case 0xD87: return "Cortex-A725";
        case 0xD85: return "Cortex-X925";
        case 0xD8B: return "C1-Pro";
        case 0xD8C: return "C1-Ultra";
        case 0xD90: return "C1-Premium";
        default:    return "ARM core";
        }
    case 0x51: /* Qualcomm */
        switch (part_number) {
        case 0x001: return "Oryon";
        case 0x802: return "Kryo Gold (A75-class)";
        case 0x804: return "Kryo Gold/Prime";
        case 0x803: case 0x805: return "Kryo Silver";
        default:    return "Kryo core";
        }
    case 0x53: /* Samsung */
        return "Exynos Mongoose";
    default:
        return "CPU core";
    }
}

/*============================================================================
 * CPU Temperature
 *============================================================================*/

#define MAX_THERMAL_ZONES 16

static int g_cpu_thermal_zones[MAX_THERMAL_ZONES];
static int g_num_cpu_zones = 0;
/* One-time zone discovery: get_cpu_temp() is called concurrently by the
 * display and API threads; a plain "init flag set before the arrays fill"
 * pattern let a second caller read a half-populated zone list. */
static pthread_once_t g_thermal_once = PTHREAD_ONCE_INIT;

static void detect_thermal_zones(void) {
#ifdef __linux__
    int fallback_zones[MAX_THERMAL_ZONES];
    int num_fallback = 0;

    g_num_cpu_zones = 0;

    /* MediaTek BSPs commonly expose dozens of zones; scan a wide range. */
    for (int z = 0; z < 128 && g_num_cpu_zones < MAX_THERMAL_ZONES; z++) {
        char path[128];
        char type[64] = {0};
        FILE *f;

        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/type", z);
        f = fopen(path, "r");
        if (!f) continue;
        if (fgets(type, sizeof(type), f)) {
            // Strip newline
            char *nl = strchr(type, '\n');
            if (nl) *nl = '\0';
        }
        fclose(f);

        // Match CPU-related thermal zones
        // Common names: cpu-thermal, soc-thermal, bigcore0-thermal,
        // littlecore-thermal, cpu_thermal, tsens_tz_sensor (Qualcomm),
        // mtkts* (MediaTek), BIG/MID/LITTLE (Exynos)
        if (strstr(type, "cpu") || strstr(type, "CPU") ||
            strstr(type, "soc") || strstr(type, "SOC") ||
            strstr(type, "bigcore") || strstr(type, "littlecore") ||
            strstr(type, "tsens") || strstr(type, "mtkts") ||
            strstr(type, "BIG") || strstr(type, "MID") ||
            strstr(type, "LITTLE") || strstr(type, "cluster")) {
            g_cpu_thermal_zones[g_num_cpu_zones++] = z;
        } else if (num_fallback < MAX_THERMAL_ZONES) {
            /* Zone exists but the OEM name didn't match — remember it so
             * unmatched platforms still report the hottest readable zone
             * instead of nothing. */
            fallback_zones[num_fallback++] = z;
        }
    }

    /* No CPU-named zone anywhere: fall back to every existing zone. Under
     * mining load the CPU/SoC zone is the hottest, so max() over all of
     * them is a good proxy. Cached once — individual zones that fail to
     * read (sepolicy, disabled sensors) are skipped per read, and must NOT
     * abort the others (MediaTek zone 0 is often one of the broken ones). */
    if (g_num_cpu_zones == 0) {
        for (int i = 0; i < num_fallback; i++)
            g_cpu_thermal_zones[g_num_cpu_zones++] = fallback_zones[i];
    }
#endif
}

static int read_thermal_zone_temp(int z)
{
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", z);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    int temp = 0;
    int ok = fscanf(f, "%d", &temp);
    fclose(f);
    if (ok != 1)
        return -1;
    /* Most zones report millidegrees; some (older kernels) report degrees */
    if (temp > 1000) temp /= 1000;
    /* Sanity-check: ignore obviously bogus readings */
    if (temp < 1 || temp > 150)
        return -1;
    return temp;
}

int get_cpu_temp(void) {
#ifdef __linux__
    pthread_once(&g_thermal_once, detect_thermal_zones);

    int max_temp = -1;

    /* Detection cached the zone list (CPU-named zones, or every existing
     * zone when no name matched). Unreadable zones return -1 and are simply
     * skipped — never abort the scan on one bad zone. */
    for (int i = 0; i < g_num_cpu_zones; i++) {
        int t = read_thermal_zone_temp(g_cpu_thermal_zones[i]);
        if (t > max_temp) max_temp = t;
    }

    return max_temp;
#else
    return -1;
#endif
}
