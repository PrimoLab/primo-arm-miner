#ifndef CPU_FEATURES_H_
#define CPU_FEATURES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

// CPU capability flags
typedef struct {
    bool has_aes;           // ARMv8 AES encryption support
    bool has_pmull;         // ARMv8 polynomial multiplication support
    bool has_asimd;         // Advanced SIMD (NEON) support
    bool has_armv8_crypto;  // Both AES and PMULL available
} cpu_capabilities_t;

// Detect CPU features at runtime
cpu_capabilities_t detect_cpu_features(void);

// Check if ARMv8 crypto extensions are available
bool has_armv8_crypto_support(void);

// Global CPU capabilities (initialized once at startup)
extern cpu_capabilities_t g_cpu_caps;

// Initialize CPU feature detection (call once at program startup)
void init_cpu_features(void);

// --- Core topology detection ---

#define ARM_PART_CORTEX_A55  0xD05
#define ARM_PART_CORTEX_A76  0xD0B
#define MAX_CPUS 64

typedef struct {
    int cpu_id;
    int part_number;    // ARM part number (0xD05=A55, 0xD0B=A76)
    bool is_big;        // true for performance cores
    int max_freq_khz;
} cpu_core_info_t;

extern cpu_core_info_t g_cpu_cores[MAX_CPUS];
extern int g_num_cpus;
extern int g_num_big_cores;
extern int g_num_little_cores;

// Sorted list: big cores first (highest freq), then little cores
extern int g_core_order[MAX_CPUS];
extern int g_core_order_count;

void detect_cpu_topology(void);
int get_cpu_for_thread(int thr_id);

// Current operating frequency of a logical CPU in kHz (-1 if unreadable).
int get_cpu_cur_freq_khz(int cpu_id);
// Human-readable core name for a MIDR part number (e.g. "Cortex-X1").
const char *cpu_part_name(int part_number);

// Hotplug support: Android parks/wakes cores at runtime, so startup topology
// is a snapshot. online_changed() compares the kernel's online-CPU mask
// against the last detection; refresh() re-scans. Callers must serialize
// refresh() against concurrent topology readers themselves.
bool cpu_topology_online_changed(void);
void cpu_topology_refresh(void);

// --- CPU temperature ---
// Returns highest CPU thermal zone temp in degrees C, or -1 if unavailable
int get_cpu_temp(void);

#ifdef __cplusplus
}
#endif

#endif // CPU_FEATURES_H_