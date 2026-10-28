package io.linscp.commander

import android.app.Activity
import android.content.Context
import android.net.Uri
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.result.ActivityResultLauncher
import org.json.JSONObject

/**
 * Aggregate Tauri plugin that exposes Android-specific commands to the
 * TypeScript `TransportClient`. In a full Tauri build these are registered
 * as `#[tauri::command]`; in this scaffold they are also exposed via
 * `WebView.addJavascriptInterface` so the UI can run in an embedded WebView
 * without a full Tauri runtime (useful for CI `assembleDebug` smoke tests).
 */
object LinScpTauriPlugin {

    private var webViewRef: WebView? = null
    private var contextRef: Context? = null
    private var safLauncherRef: ActivityResultLauncher<Uri?>? = null

    fun attachWebView(
        webView: WebView,
        activity: Activity,
        safLauncher: ActivityResultLauncher<Uri?>,
    ) {
        webViewRef = webView
        contextRef = activity
        safLauncherRef = safLauncher
        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true
        webView.addJavascriptInterface(Bridge(), "LinSCPAndroid")
        webView.loadUrl("file:///android_asset/ui-dist/index.html")
    }

    class Bridge {
        @JavascriptInterface
        fun requestSafTree(): String {
            (contextRef as? MainActivity)?.requestSafTree()
            return JSONObject().put("success", true).toString()
        }

        @JavascriptInterface
        fun getGrantedTrees(): String {
            val ctx = contextRef ?: return "[]"
            val roots = LinScpSafPlugin.listGrantedRoots(ctx)
            val arr = org.json.JSONArray()
            for (r in roots) {
                arr.put(JSONObject().apply {
                    put("path", r.path)
                    put("label", r.label)
                    put("kind", r.kind)
                    put("read_only", false)
                })
            }
            return arr.toString()
        }

        @JavascriptInterface
        fun foregroundStart(title: String, ongoing: Int): String {
            val ctx = contextRef ?: return errorJson("no context")
            return try {
                LinScpForegroundService.start(ctx, title, ongoing)
                JSONObject().put("success", true).toString()
            } catch (e: Exception) {
                errorJson(e.message ?: "foreground start failed")
            }
        }

        @JavascriptInterface
        fun foregroundStop(): String {
            val ctx = contextRef ?: return errorJson("no context")
            LinScpForegroundService.stop(ctx)
            return JSONObject().put("success", true).toString()
        }

        private fun errorJson(msg: String): String =
            JSONObject().put("success", false).put("error", msg).toString()
    }

    fun emitSafTreeGranted(uri: String) {
        webViewRef?.post {
            webViewRef?.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('linscp:saf-granted',{detail:{uri:'$uri'}}))",
                null,
            )
        }
    }

    fun emitShareStaged(id: String, paths: List<String>) {
        val jsonPaths = paths.joinToString(",") { "\"$it\"" }
        webViewRef?.post {
            webViewRef?.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('linscp:share-staged',{detail:{id:'$id',paths:[$jsonPaths]}}))",
                null,
            )
        }
    }

    fun emitCancelTransfers() {
        webViewRef?.post {
            webViewRef?.evaluateJavascript(
                "window.dispatchEvent(new CustomEvent('linscp:cancel-transfers'))",
                null,
            )
        }
    }
}
