package io.linscp.commander

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import java.io.File
import java.util.UUID

/**
 * Share Sheet plugin – handles `ACTION_SEND` / `ACTION_SEND_MULTIPLE`
 * by copying incoming `content://` streams into app-private
 * `share-staging/<id>/` and writing a `shell-manifests/{id}.json`
 * so the Rust `CommanderService` can prompt:
 * “N file(s) from Android Share Sheet – upload to current tab?”.
 *
 * This mirrors the Linux `--shell-upload` manifest flow.
 */
object LinScpSharePlugin {

    private fun stagingRoot(context: Context): File =
        File(context.filesDir, "share-staging").also { it.mkdirs() }

    private fun manifestDir(context: Context): File {
        val cfg = LinScpKeystorePlugin.configDir(context)
        return File(cfg, "shell-manifests").also { it.mkdirs() }
    }

    fun stageSingleShare(context: Context, uri: Uri) {
        stageMultipleShares(context, listOf(uri))
    }

    fun stageMultipleShares(context: Context, uris: List<Uri>) {
        if (uris.isEmpty()) return
        val stagedPaths = mutableListOf<String>()
        val id = UUID.randomUUID().toString().replace("-", "").take(16)
        val stagingDir = File(stagingRoot(context), id).also { it.mkdirs() }

        for (uri in uris) {
            try {
                val staged = copyUriToStaging(context, uri, stagingDir) ?: continue
                stagedPaths.add(staged.absolutePath)
            } catch (e: Exception) {
                Log.w("LinSCP/Share", "Failed to stage $uri", e)
            }
        }
        if (stagedPaths.isEmpty()) return
        writeShellManifest(context, id, stagedPaths, manifestDir(context))
        Log.i("LinSCP/Share", "Staged ${stagedPaths.size} share files id=$id")
        LinScpTauriPlugin.emitShareStaged(id, stagedPaths)
    }

    private fun copyUriToStaging(context: Context, uri: Uri, stagingDir: File): File? {
        val resolver = context.contentResolver
        val displayName = resolver.query(uri, null, null, null, null)?.use { cursor ->
            val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst() && idx >= 0) cursor.getString(idx) else null
        } ?: uri.lastPathSegment?.substringAfterLast('/') ?: "shared-file"

        val safeName = displayName.replace('/', '_').replace('\u0000', '_').ifBlank { "shared-file" }
        var target = File(stagingDir, safeName)
        var counter = 1
        while (target.exists()) {
            val stem = safeName.substringBeforeLast('.', safeName)
            val ext = if ('.' in safeName) ".${safeName.substringAfterLast('.')}" else ""
            target = File(stagingDir, "${stem}-$counter$ext")
            counter++
        }

        resolver.openInputStream(uri)?.use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        } ?: return null

        // Preserve execute permission for scripts? Not needed – 0600 via app-private dir.
        return target
    }

    private fun writeShellManifest(
        context: Context,
        id: String,
        stagedPaths: List<String>,
        manifestDir: File,
    ) {
        val items = stagedPaths.map { absPath ->
            val f = File(absPath)
            """
            {"path":"${f.absolutePath.replace("\\", "\\\\").replace("\"", "\\\"")}","name":"${f.name.replace("\"", "\\\"")}","size":${f.length()},"is_dir":false,"is_symlink":false}
            """.trimIndent()
        }.joinToString(",")

        val created = System.currentTimeMillis() / 1000
        val json = """{"id":"$id","created":$created,"items":[$items],"source":"android_share"}"""
        File(manifestDir, "$id.json").writeText(json)
    }

    /** Called from Rust `ShareBridge::staged_share_paths` – returns staged file paths */
    fun stagedSharePaths(context: Context): List<String> {
        val root = stagingRoot(context)
        if (!root.exists()) return emptyList()
        return root.walkTopDown()
            .filter { it.isFile }
            .map { it.absolutePath }
            .toList()
    }

    /** Explicit staging for Rust-initiated `stage_uris` – copies content:// URIs */
    fun stageUris(context: Context, uriStrings: List<String>): List<String> {
        val uris = uriStrings.mapNotNull { runCatching { Uri.parse(it) }.getOrNull() }
        if (uris.isEmpty()) return emptyList()
        val id = UUID.randomUUID().toString().replace("-", "").take(16)
        val stagingDir = File(stagingRoot(context), id).also { it.mkdirs() }
        val staged = mutableListOf<String>()
        for (uri in uris) {
            copyUriToStaging(context, uri, stagingDir)?.let { staged.add(it.absolutePath) }
        }
        return staged
    }
}
