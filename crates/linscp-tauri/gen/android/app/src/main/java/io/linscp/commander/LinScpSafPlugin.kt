package io.linscp.commander

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import org.json.JSONArray
import org.json.JSONObject

/**
 * SAF plugin – manages user-granted document trees (`ACTION_OPEN_DOCUMENT_TREE`)
 * and exposes `content://` operations to the Rust `SafBridge` via Tauri IPC.
 *
 * On Android 11+ only persisted tree URIs (via `takePersistableUriPermission`)
 * survive process death. The granted set is stored in SharedPreferences and
 * re-hydrated at launch.
 */
object LinScpSafPlugin {

    private const val PREFS = "linscp_saf_prefs"
    private const val KEY_TREES = "granted_trees"

    fun persistedTrees(context: Context): List<Uri> {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getStringSet(KEY_TREES, emptySet()) ?: emptySet()
        return raw.mapNotNull { runCatching { Uri.parse(it) }.getOrNull() }
    }

    fun onTreeGranted(context: Context, treeUri: Uri) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val current = prefs.getStringSet(KEY_TREES, mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        current.add(treeUri.toString())
        prefs.edit().putStringSet(KEY_TREES, current).apply()
        Log.i("LinSCP/SAF", "Tree granted: $treeUri")
        // Emit Tauri event so LocalRootSwitcher can refresh
        LinScpTauriPlugin.emitSafTreeGranted(treeUri.toString())
    }

    fun listGrantedRoots(context: Context): List<SafRoot> {
        return persistedTrees(context).map { uri ->
            val docFile = DocumentFile.fromTreeUri(context, uri)
            SafRoot(
                path = uri.toString(),
                label = docFile?.name?.let { "$it (SAF)" } ?: "SAF Folder",
                kind = "saf_tree",
            )
        }
    }

    data class SafRoot(val path: String, val label: String, val kind: String)

    fun listTree(context: Context, treeUri: String): JSONArray {
        val uri = Uri.parse(treeUri)
        val treeDoc = DocumentFile.fromTreeUri(context, uri) ?: return JSONArray()
        // For a tree URI, list top-level children. For a document URI, list that folder.
        val target = if (DocumentsContract.isTreeUri(uri)) treeDoc else DocumentFile.fromSingleUri(context, uri) ?: treeDoc
        val children = target.listFiles()
        val arr = JSONArray()
        for (child in children) {
            val obj = JSONObject()
            obj.put("name", child.name ?: "unknown")
            obj.put("size", child.length())
            obj.put("is_dir", child.isDirectory)
            obj.put("is_symlink", false)
            obj.put("broken_link", false)
            obj.put("mtime", child.lastModified() / 1000)
            obj.put("permissions", if (child.isDirectory) "drwxr-xr-x" else "-rw-r--r--")
            arr.put(obj)
        }
        return arr
    }

    fun statUri(context: Context, uriString: String): JSONObject? {
        val uri = Uri.parse(uriString)
        val doc = DocumentFile.fromSingleUri(context, uri) ?: DocumentFile.fromTreeUri(context, uri)
        doc ?: return null
        return JSONObject().apply {
            put("name", doc.name ?: uri.lastPathSegment ?: "unknown")
            put("size", doc.length())
            put("is_dir", doc.isDirectory)
            put("is_symlink", false)
            put("broken_link", false)
            put("mtime", doc.lastModified() / 1000)
            put("permissions", if (doc.isDirectory) "drwxr-xr-x" else "-rw-r--r--")
        }
    }

    fun readUriBytes(context: Context, uriString: String): ByteArray {
        val uri = Uri.parse(uriString)
        context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalArgumentException("Cannot open SAF URI: $uriString")
    }

    fun writeUriBytes(context: Context, parentUri: String, name: String, data: ByteArray): String {
        val parent = DocumentFile.fromTreeUri(context, Uri.parse(parentUri))
            ?: throw IllegalArgumentException("Invalid parent URI: $parentUri")
        val sanitized = name.replace('/', '_').replace('\u0000', '_')
        val mime = when {
            sanitized.endsWith(".txt", true) -> "text/plain"
            sanitized.endsWith(".json", true) -> "application/json"
            else -> "application/octet-stream"
        }
        val child = parent.createFile(mime, sanitized)
            ?: throw IllegalStateException("Failed to create SAF file: $sanitized in $parentUri")
        context.contentResolver.openOutputStream(child.uri)?.use { it.write(data) }
            ?: throw IllegalStateException("Failed to open output stream for ${child.uri}")
        return child.uri.toString()
    }

    fun mkdirUri(context: Context, parentUri: String, name: String): String {
        val parent = DocumentFile.fromTreeUri(context, Uri.parse(parentUri))
            ?: throw IllegalArgumentException("Invalid parent URI: $parentUri")
        val sanitized = name.replace('/', '_')
        val dir = parent.createDirectory(sanitized)
            ?: throw IllegalStateException("Failed to create directory: $sanitized")
        return dir.uri.toString()
    }

    fun deleteUri(context: Context, uriString: String): Boolean {
        val doc = DocumentFile.fromSingleUri(context, Uri.parse(uriString))
            ?: DocumentFile.fromTreeUri(context, Uri.parse(uriString))
            ?: return false
        return doc.delete()
    }

    fun renameUri(context: Context, uriString: String, newName: String): String {
        val doc = DocumentFile.fromSingleUri(context, Uri.parse(uriString))
            ?: throw IllegalArgumentException("Cannot resolve URI: $uriString")
        val sanitized = newName.replace('/', '_')
        if (!doc.renameTo(sanitized)) throw IllegalStateException("Rename failed")
        // After rename, the URI may change – re-query via parent listing
        return doc.uri.toString()
    }
}
