package dev.primolab.miner

import android.content.Context
import org.json.JSONObject
import java.io.File

/**
 * Per-algorithm config profiles, stored app-side in profiles.json. Lets the user
 * keep separate pool/wallet/threads for verus / sha256d / scrypt and switch
 * between them without re-entering anything.
 *
 * The native miner is unchanged: it still reads a single flat config.json. On
 * save we flatten the ACTIVE algo's profile into config.json (what MinerService
 * launches with); profiles.json is purely the app's memory of the others.
 *
 * profiles.json shape:
 *   { "active": "verus",
 *     "algos": { "verus": {url,user,pass,threads}, "sha256d": {...}, ... } }
 */
object ProfileStore {

    val ALGOS = listOf("verus", "sha256d", "scrypt")

    data class Profile(
        var url: String = "",
        var user: String = "",
        var pass: String = "x",
        var threads: Int = 4,
    )

    private fun file(ctx: Context) = File(ctx.filesDir, "profiles.json")

    private fun load(ctx: Context): JSONObject {
        val f = file(ctx)
        if (f.exists()) {
            runCatching { return JSONObject(f.readText()) }
        }
        // Migrate an existing single config.json into its algo's profile.
        val root = JSONObject().put("active", ALGOS[0]).put("algos", JSONObject())
        val legacy = MinerService.configFile(ctx)
        if (legacy.exists()) {
            runCatching {
                val j = JSONObject(legacy.readText())
                val algo = j.optString("algo", ALGOS[0])
                root.put("active", algo)
                root.getJSONObject("algos").put(algo, JSONObject()
                    .put("url", j.optString("url"))
                    .put("user", j.optString("user"))
                    .put("pass", j.optString("pass", "x"))
                    .put("threads", j.optInt("threads", 4)))
            }
        }
        return root
    }

    fun activeAlgo(ctx: Context): String =
        load(ctx).optString("active", ALGOS[0]).let { if (it in ALGOS) it else ALGOS[0] }

    /**
     * App-wide (not per-algo) flag: expose the status API to the LAN. Off = the
     * miner binds 127.0.0.1 (in-app dashboard only); on = 0.0.0.0 (other devices
     * on the network can reach the ccminer-compatible API on port 4068).
     */
    fun lanApi(ctx: Context): Boolean = load(ctx).optBoolean("lanApi", false)

    fun setLanApi(ctx: Context, on: Boolean) {
        file(ctx).writeText(load(ctx).put("lanApi", on).toString())
    }

    fun profile(ctx: Context, algo: String): Profile {
        val algos = load(ctx).optJSONObject("algos") ?: return Profile()
        val j = algos.optJSONObject(algo) ?: return Profile()
        return Profile(
            url = j.optString("url"),
            user = j.optString("user"),
            pass = j.optString("pass", "x"),
            threads = j.optInt("threads", 4),
        )
    }

    /** Persist one algo's profile (does not change which algo is active). */
    fun saveProfile(ctx: Context, algo: String, p: Profile) {
        val root = load(ctx)
        val algos = root.optJSONObject("algos") ?: JSONObject().also { root.put("algos", it) }
        algos.put(algo, JSONObject()
            .put("url", p.url).put("user", p.user)
            .put("pass", p.pass).put("threads", p.threads))
        file(ctx).writeText(root.toString())
    }

    /**
     * Mark [algo] active, save its profile, and flatten it into config.json so the
     * miner launches with it. Returns true if the profile has a usable URL.
     */
    fun commitActive(ctx: Context, algo: String, p: Profile): Boolean {
        saveProfile(ctx, algo, p)
        val root = load(ctx).put("active", algo)
        file(ctx).writeText(root.toString())
        MinerService.configFile(ctx).writeText(JSONObject()
            .put("algo", algo).put("url", p.url).put("user", p.user)
            .put("pass", p.pass).put("threads", p.threads)
            .toString(2))
        return p.url.isNotBlank()
    }
}
