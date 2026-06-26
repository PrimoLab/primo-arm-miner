package dev.primolab.miner

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.ColorStateList
import android.graphics.Color
import android.net.Uri
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.concurrent.thread

/**
 * Page 1 (home) — mining dashboard. Big hashrate, per-thread chips, a stat grid,
 * and a Start/Stop pill. Config is reached via the cog in the action bar.
 * All data comes from the miner's read-only API (127.0.0.1:4068) + Android battery.
 */
class MiningActivity : Activity() {

    private val handler = Handler(Looper.getMainLooper())
    private var mining = false
    private var maxKhs = 0.0

    private lateinit var hashrate: TextView
    private lateinit var algo: TextView
    private lateinit var pool: TextView
    private lateinit var status: TextView
    private lateinit var statusDot: View
    private lateinit var threadWrap: LinearLayout
    private lateinit var startStop: Button

    private val ACCENT = Color.parseColor("#19E3A1")
    private val IDLE = Color.parseColor("#2A2E3A")
    private val DARK = Color.parseColor("#0B0C10")
    private val WARN = Color.parseColor("#FFB020")
    private val DANGER = Color.parseColor("#FF5566")
    private val DIM = Color.parseColor("#828A9A")
    private val TEXT = Color.parseColor("#F2F4F8")

    private val poller = object : Runnable {
        override fun run() {
            thread {
                val s = ApiClient.summary()
                val t = ApiClient.threads()
                val hw = ApiClient.hwinfo()
                runOnUiThread { render(s, t, hw) }
            }
            handler.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_mining)
        hashrate = findViewById(R.id.hashrateText)
        algo = findViewById(R.id.algoText)
        pool = findViewById(R.id.poolText)
        status = findViewById(R.id.statusText)
        statusDot = findViewById(R.id.statusDot)
        threadWrap = findViewById(R.id.threadWrap)
        startStop = findViewById(R.id.startStopButton)
        setPill(false)
        startStop.setOnClickListener { if (mining) stopMining() else startMining() }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.mining_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.action_config -> {
                startActivity(Intent(this, ConfigActivity::class.java)); return true
            }
            R.id.action_logs -> {
                startActivity(Intent(this, LogActivity::class.java)); return true
            }
        }
        return super.onOptionsItemSelected(item)
    }

    override fun onResume() { super.onResume(); handler.post(poller) }
    override fun onPause() { super.onPause(); handler.removeCallbacks(poller) }

    private fun startMining() {
        if (!MinerService.configFile(this).exists()) {
            setStatus("NO CONFIG — TAP THE COG", WARN)
            return
        }
        requestIgnoreBatteryOptimizations()
        val intent = Intent(this, MinerService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent)
        else startService(intent)
        mining = true
        maxKhs = 0.0
        setPill(true)
        // Focused, on-screen app = top-app = all cores + uclamp boost (no root).
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    private fun stopMining() {
        stopService(Intent(this, MinerService::class.java))
        mining = false
        setPill(false)
        setStatus(getString(R.string.status_idle), DIM)
        threadWrap.removeAllViews()
        threadWrap.visibility = View.GONE
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    private fun setPill(active: Boolean) {
        startStop.text = if (active) getString(R.string.stop) else getString(R.string.start)
        startStop.backgroundTintList =
            ColorStateList.valueOf(if (active) Color.parseColor("#FF5566") else ACCENT)
    }

    private fun render(s: Map<String, String>?, t: List<Map<String, String>>?, hw: Map<String, String>?) {
        renderBattery()
        if (s == null) {
            hashrate.text = "0.00 MH/s"
            // Show the configured algo/pool so the hero isn't blank while idle.
            val cfgAlgo = ProfileStore.activeAlgo(this)
            algo.text = cfgAlgo.uppercase()
            pool.text = ProfileStore.profile(this, cfgAlgo).url.substringAfter("://").ifBlank { "—" }
            if (mining) setStatus("CONNECTING…", WARN)
            else setStatus(getString(R.string.status_idle), DIM)
            return
        }
        mining = true; setPill(true)

        val khs = s["KHS"]?.toDoubleOrNull() ?: 0.0
        if (khs > maxKhs) maxKhs = khs
        hashrate.text = fmtRate(khs)
        algo.text = s["ALGO"]?.uppercase() ?: "—"
        pool.text = ProfileStore.profile(this, ProfileStore.activeAlgo(this))
            .url.substringAfter("://").ifBlank { "—" }
        if (khs > 0.0) setStatus("MINING", ACCENT) else setStatus("CONNECTING…", WARN)

        setVal(R.id.valAccepted, s["ACC"] ?: "0")
        val rej = s["REJ"]?.toIntOrNull() ?: 0
        setValColored(R.id.valRejected, (s["REJ"] ?: "0"), if (rej > 0) DANGER else TEXT)
        setVal(R.id.valDiff, fmtDiff(s["DIFF"]))
        setVal(R.id.valUptime, fmtUptime(s["UPTIME"]?.toDoubleOrNull() ?: 0.0))
        setVal(R.id.valMaxhash, fmtRate(maxKhs))
        val temp = hw?.get("CPUTEMP")?.toIntOrNull() ?: 0
        setValColored(R.id.valTemp, if (temp > 0) "$temp °C" else "—", tempColor(temp))

        renderThreads(t)
    }

    /** Status pill: set label + tint both the text and the leading dot. */
    private fun setStatus(label: String, color: Int) {
        status.text = label
        status.setTextColor(color)
        statusDot.backgroundTintList = ColorStateList.valueOf(color)
    }

    private fun tempColor(t: Int): Int = when {
        t <= 0 -> TEXT
        t >= 83 -> DANGER
        t >= 72 -> WARN
        else -> TEXT
    }

    private fun renderThreads(list: List<Map<String, String>>?) {
        threadWrap.removeAllViews()
        if (list.isNullOrEmpty()) { threadWrap.visibility = View.GONE; return }
        threadWrap.visibility = View.VISIBLE
        val dp = resources.displayMetrics.density
        val sorted = list.sortedBy { it["GPU"]?.toIntOrNull() ?: 0 }

        // Wrap onto centered rows so 8/10/12+ threads never scroll off-screen.
        // Balance rows evenly (12 -> 6+6, not 8+4) for a tidy grid.
        val chipFootprint = 40f * dp                       // chip min-width + margin
        val avail = resources.displayMetrics.widthPixels - (32f * dp)
        val maxPerRow = maxOf(1, (avail / chipFootprint).toInt())
        val rows = (sorted.size + maxPerRow - 1) / maxPerRow
        val perRow = (sorted.size + rows - 1) / rows

        var row: LinearLayout? = null
        sorted.forEachIndexed { i, th ->
            if (i % perRow == 0) {
                row = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER
                }
                val rlp = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                rlp.topMargin = if (i == 0) 0 else (6 * dp).toInt()
                threadWrap.addView(row, rlp)
            }
            val active = (th["KHS"]?.toDoubleOrNull() ?: 0.0) > 0.0
            val chip = TextView(this).apply {
                text = th["GPU"] ?: "?"
                textSize = 13f
                setTypeface(typeface, android.graphics.Typeface.BOLD)
                gravity = Gravity.CENTER
                minWidth = (34 * dp).toInt()             // uniform width across single digits
                setTextColor(if (active) DARK else DIM)
                background = resources.getDrawable(R.drawable.thread_chip, theme)
                backgroundTintList = ColorStateList.valueOf(if (active) ACCENT else IDLE)
                val padH = (6 * dp).toInt(); val padV = (7 * dp).toInt()
                setPadding(padH, padV, padH, padV)
            }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            lp.marginEnd = (5 * dp).toInt()
            row!!.addView(chip, lp)
        }
    }

    private fun renderBattery() {
        val bi = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val level = bi?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = bi?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val pct = if (level >= 0 && scale > 0) level * 100 / scale else -1
        setVal(R.id.valBattery, if (pct >= 0) "$pct %" else "—")
        setVal(R.id.valCharge, when (bi?.getIntExtra(BatteryManager.EXTRA_STATUS, -1)) {
            BatteryManager.BATTERY_STATUS_CHARGING -> "Charging"
            BatteryManager.BATTERY_STATUS_FULL -> "Full"
            else -> "Discharging"
        })
    }

    private fun setVal(id: Int, v: String) { findViewById<TextView>(id).text = v }

    private fun setValColored(id: Int, v: String, color: Int) {
        findViewById<TextView>(id).apply { text = v; setTextColor(color) }
    }

    private fun fmtRate(khs: Double): String =
        if (khs >= 1000) "%.2f MH/s".format(khs / 1000.0) else "%.2f kH/s".format(khs)

    private fun fmtDiff(d: String?): String {
        val v = d?.toDoubleOrNull() ?: return "—"
        return if (v >= 100) v.toLong().toString() else "%.3f".format(v)
    }

    private fun fmtUptime(sec: Double): String = when {
        sec < 60 -> "${sec.toInt()}s"
        sec < 3600 -> "${(sec / 60).toInt()}m"
        else -> "%.1fh".format(sec / 3600.0)
    }

    private fun requestIgnoreBatteryOptimizations() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        try {
            startActivity(Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:$packageName")))
        } catch (_: Exception) {}
    }
}
