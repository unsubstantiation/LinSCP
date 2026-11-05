package io.linscp.commander

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.util.UUID

@InvokeArg
class ExportOptions { lateinit var path: String }

/** Explicit copy-in/copy-out through Android's system document picker.
 * It does not pretend that a content URI is a POSIX filesystem path. */
@TauriPlugin
class StoragePlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun importFiles(invoke: Invoke) {
        try {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
                putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
            }
            startActivityForResult(invoke, intent, "importResult")
        } catch (error: Exception) { invoke.reject(error.message ?: "Cannot open document picker") }
    }

    @ActivityCallback
    fun importResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK) { invoke.reject("Document selection cancelled"); return }
        val data = result.data
        val uris = if (data?.clipData != null) {
            (0 until data.clipData!!.itemCount).map { data.clipData!!.getItemAt(it).uri }
        } else listOfNotNull(data?.data)
        if (uris.isEmpty() || uris.size > 64) { invoke.reject("Select between 1 and 64 files"); return }
        Thread {
            var batch: File? = null
            try {
                val parent = File(activity.filesDir, "Imports")
                if (!parent.isDirectory && !parent.mkdirs()) error("Cannot create import directory")
                batch = File(parent, UUID.randomUUID().toString())
                if (!batch.mkdir()) error("Cannot create import batch")
                val names = mutableSetOf<String>()
                for ((index, uri) in uris.withIndex()) {
                    val name = safeName(displayName(uri) ?: "import-${index + 1}")
                    if (!names.add(name)) error("Selected files have duplicate names: $name")
                    val target = File(batch, name)
                    if (!target.createNewFile()) error("Import destination already exists")
                    val input = activity.contentResolver.openInputStream(uri) ?: error("Cannot open selected document")
                    input.use { source -> target.outputStream().use { sink -> source.copyTo(sink) } }
                }
                val response = JSObject()
                response.put("directory", batch.absolutePath)
                response.put("count", uris.size)
                invoke.resolve(response)
            } catch (error: Exception) {
                batch?.deleteRecursively()
                invoke.reject("Import failed: ${error.message ?: "unknown error"}")
            }
        }.start()
    }

    private fun displayName(uri: Uri): String? {
        activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst() && !cursor.isNull(0)) return cursor.getString(0)
        }
        return null
    }

    private fun safeName(raw: String): String {
        val name = raw.map { if (it == '/' || it == '\\' || it == ':' || it.isISOControl()) '_' else it }.joinToString("").trim()
        if (name.isEmpty() || name == "." || name == ".." || name.length > 200) error("Invalid document name")
        return name
    }

    private fun selectedFile(path: String): File {
        val source = File(path)
        val root = File(activity.applicationInfo.dataDir).canonicalFile
        val canonical = source.canonicalFile
        if (!canonical.path.startsWith(root.path + File.separator) || !source.isFile || java.nio.file.Files.isSymbolicLink(source.toPath())) {
            error("Only regular app-private files can be exported")
        }
        val config = File(root, "config").canonicalFile
        if (canonical.path.startsWith(config.path + File.separator)) error("Configuration files cannot be exported")
        return source
    }

    @Command
    fun exportFile(invoke: Invoke) {
        try {
            val source = selectedFile(invoke.parseArgs(ExportOptions::class.java).path)
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_TITLE, source.name)
            }
            startActivityForResult(invoke, intent, "exportResult")
        } catch (error: Exception) { invoke.reject(error.message ?: "Cannot export file") }
    }

    @ActivityCallback
    fun exportResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK || result.data?.data == null) { invoke.reject("Document creation cancelled"); return }
        val uri = result.data!!.data!!
        Thread {
            try {
                val source = selectedFile(invoke.parseArgs(ExportOptions::class.java).path)
                val output = activity.contentResolver.openOutputStream(uri, "w") ?: error("Cannot open selected destination")
                source.inputStream().use { input -> output.use { sink -> input.copyTo(sink) } }
                invoke.resolve(JSObject())
            } catch (error: Exception) {
                invoke.reject("Export failed; the selected document may be incomplete: ${error.message ?: "unknown error"}")
            }
        }.start()
    }
}
