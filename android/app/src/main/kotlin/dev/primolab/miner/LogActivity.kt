package dev.primolab.miner

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.MenuItem
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

/**
 * Read-only viewer for the miner's log (filesDir/miner.log, the drained stdout
 * of the native subprocess). Tails the last chunk, strips the miner's ANSI color
 * codes, and auto-refreshes while visible. Reached from the log icon in the
 * MiningActivity action bar.
 */
class LogActivity : Activity() {

    private val handler = Handler(Looper.getMainLooper())
    private val ansi = Regex("\u001B?\\[[0-9;]*m")   // strip the miner's color codes
    private lateinit var text: TextView
    private lateinit var scroll: ScrollView

    private val refresh = object : Runnable {
        override fun run() { load(); handler.postDelayed(this, 2000) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_log)
        actionBar?.setDisplayHomeAsUpEnabled(true)
        actionBar?.title = getString(R.string.logs_title)
        text = findViewById(R.id.logText)
        scroll = findViewById(R.id.logScroll)
    }

    override fun onResume() { super.onResume(); handler.post(refresh) }
    override fun onPause() { super.onPause(); handler.removeCallbacks(refresh) }

    private fun load() {
        val f = File(filesDir, "miner.log")
        val raw = when {
            !f.exists() || f.length() == 0L -> "No log yet — start mining first."
            else -> try {
                val max = 64 * 1024L                       // tail the last 64 KB
                if (f.length() > max) {
                    f.inputStream().use { it.skip(f.length() - max); it.readBytes() }
                        .toString(Charsets.UTF_8).substringAfter('\n')
                } else f.readText()
            } catch (e: Exception) { "Could not read log: ${e.message}" }
        }
        val clean = ansi.replace(raw, "").trimEnd()
        if (clean != text.text.toString()) {
            // Keep auto-scroll only when the user is already near the bottom.
            val atBottom = !scroll.canScrollVertically(1)
            text.text = clean
            if (atBottom) scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }
}
