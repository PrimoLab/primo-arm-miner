package dev.primolab.miner

import android.app.Activity
import android.os.Bundle
import android.view.MenuItem
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Spinner
import android.widget.Toast

/**
 * Page 2 — Config. Algorithm is a dropdown; each algo keeps its own
 * pool/user/pass/threads (ProfileStore), so switching algos repopulates that
 * algo's saved values. SAVE flattens the active algo into config.json for the
 * native miner — which is unchanged and still reads a single flat config.
 */
class ConfigActivity : Activity() {

    private lateinit var algoSpinner: Spinner
    private lateinit var url: EditText
    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var threads: EditText
    private lateinit var lanApi: CheckBox

    private var currentAlgo = ProfileStore.ALGOS[0]
    private var ready = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_config)
        actionBar?.setDisplayHomeAsUpEnabled(true)
        algoSpinner = findViewById(R.id.algoSpinner)
        url = findViewById(R.id.urlField)
        user = findViewById(R.id.userField)
        pass = findViewById(R.id.passField)
        threads = findViewById(R.id.threadsField)
        lanApi = findViewById(R.id.lanApiCheck)
        lanApi.isChecked = ProfileStore.lanApi(this)   // app-wide, not per-algo

        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, ProfileStore.ALGOS)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        algoSpinner.adapter = adapter

        currentAlgo = ProfileStore.activeAlgo(this)
        algoSpinner.setSelection(ProfileStore.ALGOS.indexOf(currentAlgo), false)
        loadFields(currentAlgo)
        ready = true  // ignore the programmatic selection above

        algoSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>?, v: View?, pos: Int, id: Long) {
                if (!ready) return
                val selected = ProfileStore.ALGOS[pos]
                if (selected == currentAlgo) return
                // keep edits to the algo we're leaving, then load the new one
                ProfileStore.saveProfile(this@ConfigActivity, currentAlgo, readFields())
                currentAlgo = selected
                loadFields(selected)
            }
            override fun onNothingSelected(p: AdapterView<*>?) {}
        }

        findViewById<Button>(R.id.saveButton).setOnClickListener { save() }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }

    private fun loadFields(algo: String) {
        val p = ProfileStore.profile(this, algo)
        url.setText(p.url)
        user.setText(p.user)
        pass.setText(p.pass)
        threads.setText(p.threads.toString())
    }

    private fun readFields() = ProfileStore.Profile(
        url = url.text.toString().trim(),
        user = user.text.toString().trim(),
        pass = pass.text.toString().trim(),
        threads = threads.text.toString().trim().toIntOrNull() ?: 4,
    )

    private fun save() {
        ProfileStore.setLanApi(this, lanApi.isChecked)
        ProfileStore.commitActive(this, currentAlgo, readFields())
        Toast.makeText(this, "Saved ($currentAlgo)", Toast.LENGTH_SHORT).show()
        finish()
    }
}
