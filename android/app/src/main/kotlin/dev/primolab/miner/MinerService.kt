package dev.primolab.miner

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.net.InetAddress

/**
 * Foreground service that runs the native miner as a subprocess.
 *
 * The miner ships inside the APK as lib/arm64-v8a/libprimo.so and is extracted
 * to nativeLibraryDir (the one app dir mounted executable), so we can exec it
 * directly. It reads a config.json we write to filesDir and serves the
 * read-only status API on 127.0.0.1:4068 for MiningActivity to poll.
 */
class MinerService : Service() {

    companion object {
        private const val TAG = "MinerService"
        private const val CHANNEL_ID = "mining"
        private const val NOTIF_ID = 1
        const val CONFIG_FILENAME = "config.json"

        /** Path the miner is launched with; ConfigActivity writes here. */
        fun configFile(ctx: Context): File = File(ctx.filesDir, CONFIG_FILENAME)
    }

    private var process: Process? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIF_ID, buildNotification("Mining…"))
        acquireWakeLock()
        // Must run off the main thread: it resolves DNS (see prepareLaunchConfig).
        Thread { startMiner() }.apply { isDaemon = true }.start()
        return START_STICKY
    }

    private fun startMiner() {
        if (process != null) return
        val binary = File(applicationInfo.nativeLibraryDir, "libprimo.so")
        if (!binary.exists()) {
            Log.e(TAG, "miner binary missing: ${binary.absolutePath}")
            stopSelf()
            return
        }
        val config = configFile(this)
        if (!config.exists()) {
            Log.e(TAG, "config missing — open Configure first")
            stopSelf()
            return
        }
        val launchConfig = prepareLaunchConfig(config)
        try {
            // --api-bind enables the status API the UI polls (always on 4068).
            // Bind LAN-wide (0.0.0.0) only if the user opted in; the in-app
            // dashboard still reaches it via 127.0.0.1 either way.
            val bindHost = if (ProfileStore.lanApi(this)) "0.0.0.0" else ApiClient.HOST
            val pb = ProcessBuilder(
                binary.absolutePath,
                "-c", launchConfig.absolutePath,
                "--api-bind", "$bindHost:${ApiClient.PORT}"
            ).directory(filesDir)
                .redirectErrorStream(true)
            // Any bundled shared libs (e.g. libc++_shared.so) ship in the same
            // nativeLibraryDir as the binary; point the loader at them.
            pb.environment()["LD_LIBRARY_PATH"] = binary.parent
            process = pb.start()

            // Drain output to a log file so the pipe never blocks the miner.
            // Must never throw out of the thread — a logging failure must not
            // crash the service process.
            val log = File(filesDir, "miner.log")
            Thread {
                try {
                    process?.inputStream?.bufferedReader()?.use { reader ->
                        log.bufferedWriter().use { writer ->
                            reader.forEachLine { line ->
                                writer.write(line); writer.newLine(); writer.flush()
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "log drain stopped: ${e.message}")
                }
            }.apply { isDaemon = true }.start()

            // Best-effort: on rooted devices, pull the miner into the top-app
            // cpuset for full cores even when backgrounded. No-op without root.
            // Delayed so the mining threads exist before we move the group.
            Thread {
                try { Thread.sleep(2500) } catch (_: InterruptedException) {}
                RootBooster.boostToTopApp()
            }.apply { isDaemon = true }.start()
        } catch (e: Exception) {
            Log.e(TAG, "failed to launch miner", e)
            stopSelf()
        }
    }

    /**
     * Android's app sandbox blocks DNS for a raw native subprocess (getaddrinfo
     * fails with "Could not resolve host"), even though TCP works. So resolve
     * the pool host here on the JVM side (Android's resolver works for the app)
     * and write a runtime config with the host swapped for its IP. stratum+tcp
     * carries no hostname dependency (no TLS/SNI), so the IP is equivalent.
     * The user's editable config.json is left untouched.
     */
    private fun prepareLaunchConfig(src: File): File {
        val out = File(filesDir, "config.runtime.json")
        try {
            val json = JSONObject(src.readText())
            val url = json.optString("url")
            // e.g. stratum+tcp://host:port  ->  capture scheme / host / rest
            val m = Regex("^([a-z0-9]+(?:\\+[a-z0-9]+)?://)([^:/]+)(.*)$", RegexOption.IGNORE_CASE)
                .find(url)
            if (m != null) {
                val (scheme, host, rest) = m.destructured
                if (!host.matches(Regex("^[0-9.]+$"))) {  // skip if already an IP
                    try {
                        // Prefer IPv4: it needs no URL bracketing and avoids pools
                        // / sandboxes with flaky IPv6 routing. Fall back to a
                        // bracketed IPv6 literal ([addr]) so the host:port colon
                        // stays unambiguous to the miner's URL parser.
                        val addrs = InetAddress.getAllByName(host)
                        val v4 = addrs.firstOrNull { it is java.net.Inet4Address }
                        val ip = when {
                            v4 != null -> v4.hostAddress
                            else -> "[${addrs.first().hostAddress}]"
                        }
                        json.put("url", "$scheme$ip$rest")
                        Log.i(TAG, "resolved $host -> $ip")
                    } catch (e: Exception) {
                        Log.w(TAG, "DNS resolve failed for $host: ${e.message}")
                    }
                }
            }
            out.writeText(json.toString())
        } catch (e: Exception) {
            Log.w(TAG, "prepareLaunchConfig failed, using config as-is: ${e.message}")
            src.copyTo(out, overwrite = true)
        }
        return out
    }

    override fun onDestroy() {
        process?.destroy()
        process = null
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        super.onDestroy()
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "primo:miner").apply {
            acquire()
        }
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Mining", NotificationManager.IMPORTANCE_LOW)
            )
            return Notification.Builder(this, CHANNEL_ID)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setOngoing(true)
                .build()
        }
        @Suppress("DEPRECATION")
        return Notification.Builder(this)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)
            .build()
    }
}
