package io.linscp.commander

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen

class MainActivity : AppCompatActivity() {

    private val safTreeLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { treeUri: Uri? ->
        if (treeUri == null) return@registerForActivityResult
        // Persist URI permission across reboots (SAF contract)
        try {
            contentResolver.takePersistableUriPermission(
                treeUri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        } catch (e: SecurityException) {
            Log.w("LinSCP", "Failed to persist SAF permission for $treeUri", e)
        }
        // Notify WebView/JS that a new SAF tree was granted
        LinScpSafPlugin.onTreeGranted(this, treeUri)
    }

    private val biometricHelper by lazy { LinScpKeystorePlugin(this) }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)

        // BiometricPrompt gate for sessions.key (optional, respects preference)
        if (LinScpKeystorePlugin.shouldRequireBiometric(this)) {
            biometricHelper.authenticateIfNeeded(
                title = getString(R.string.app_name),
                onSuccess = { initWebView(savedInstanceState) },
                onFallback = { initWebView(savedInstanceState) },
            )
        } else {
            initWebView(savedInstanceState)
        }

        handleShareIntent(intent)
    }

    private fun initWebView(savedInstanceState: Bundle?) {
        // In a real Tauri build this delegates to TauriActivity; for phase-5
        // scaffold we load the embedded ui/dist WebView and expose the plugin
        // bridge via addJavascriptInterface. Keeps CI APK buildable without
        // full Tauri Rust compilation.
        setContentView(R.layout.activity_main)
        findViewById<android.webkit.WebView>(R.id.webview)?.let { webView ->
            LinScpTauriPlugin.attachWebView(webView, this, safTreeLauncher)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleShareIntent(intent)
    }

    private fun handleShareIntent(intent: Intent?) {
        if (intent == null) return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri = intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM) ?: return
                LinScpSharePlugin.stageSingleShare(this, uri)
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val uris = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM) ?: return
                LinScpSharePlugin.stageMultipleShares(this, uris)
            }
        }
    }

    fun requestSafTree() {
        safTreeLauncher.launch(null)
    }
}
