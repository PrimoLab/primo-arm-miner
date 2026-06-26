package dev.primolab.miner

import android.util.Log

/**
 * Optional, best-effort root booster (STUB).
 *
 * A normal APK cannot make itself `top-app` — that tier is reserved for the
 * focused app, so a backgrounded miner is throttled (cpuset core-withholding +
 * uclamp freq-cap). The ONLY way to get full cores while backgrounded/screen-off
 * is root: move the miner's threads into the `top-app` cpuset cgroup (exactly
 * what `adb shell`/`ssh` sessions get for free).
 *
 * This is a no-op without root. With root it writes the miner process into
 * /dev/cpuset/top-app/cgroup.procs (cgroup-v1; moves all current threads, and
 * threads spawned afterwards inherit the cpuset).
 *
 * STUB status: functional but minimal — no periodic re-assert, no UI toggle yet.
 */
object RootBooster {

    private const val TAG = "RootBooster"
    private const val TOP_APP_PROCS = "/dev/cpuset/top-app/cgroup.procs"

    @Volatile private var rootCache: Boolean? = null

    /** True if `su` grants root. Cached after first probe. */
    fun isRootAvailable(): Boolean {
        rootCache?.let { return it }
        val ok = runCatching {
            val p = ProcessBuilder("su", "-c", "id -u")
                .redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            out.contains("0")
        }.getOrDefault(false)
        rootCache = ok
        return ok
    }

    /**
     * Move the running miner ("libprimo.so") into the top-app cpuset.
     * Best-effort: logs and returns false if root is unavailable or it fails.
     */
    fun boostToTopApp(): Boolean {
        if (!isRootAvailable()) {
            Log.i(TAG, "no root — staying in the platform-assigned cpuset (throttled when backgrounded)")
            return false
        }
        // pidof gives the miner's pid; cgroup.procs moves the whole thread group.
        val cmd = "for p in \$(pidof libprimo.so); do echo \$p > $TOP_APP_PROCS; done"
        return runCatching {
            val p = ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            val code = p.waitFor()
            if (code == 0) {
                Log.i(TAG, "boosted miner into top-app cpuset")
                true
            } else {
                Log.w(TAG, "boost failed (exit $code): $out")
                false
            }
        }.getOrElse {
            Log.w(TAG, "boost failed: ${it.message}")
            false
        }
    }
}
