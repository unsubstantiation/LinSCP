package com.fairuniversal.linscp

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.webkit.WebView
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

@InvokeArg
internal class TreeArgs { lateinit var uri: String }
@InvokeArg
internal class UriArgs { lateinit var uris: ArrayList<String> }
@InvokeArg
internal class SingleUriArgs { lateinit var uri: String }
@InvokeArg
internal class WriteArgs { lateinit var parent_uri: String; lateinit var name: String; lateinit var data_base64: String }
@InvokeArg
internal class NameArgs { lateinit var parent_uri: String; lateinit var name: String }
@InvokeArg
internal class RenameArgs { lateinit var uri: String; lateinit var new_name: String }
@InvokeArg
internal class ForegroundStartArgs { lateinit var title: String; var ongoing: Int = 0 }
@InvokeArg
internal class ProgressArgs { var done: Long = 0; var total: Long = 0 }

/** Android implementation behind the Rust `linscp-platform::android` bridges. */
@TauriPlugin
class LinSCPAndroidPlugin(private val activity: Activity) : Plugin(activity) {
  private val running = AtomicBoolean(false)
  private val shareLock = Any()
  private val pendingShares = mutableListOf<String>()
  private val shareDir: File get() = File(activity.cacheDir, "incoming-shares")
  private val maxSharedBytes = 512L * 1024L * 1024L
  private val stageLock = Any()

  private fun <T : Any> runIo(invoke: Invoke, failurePrefix: String, action: () -> T) {
    Thread({
      val result = try { Result.success(action()) }
      catch (e: Exception) { Result.failure(e) }
      activity.runOnUiThread {
        result.fold(
          { invoke.resolveObject(it) },
          { invoke.reject("$failurePrefix: ${it.message}") },
        )
      }
    }, "linscp-android-io").start()
  }

  override fun load(webView: WebView) {
    activity.intent?.let { stageShareIntent(it) }
  }

  override fun onNewIntent(intent: Intent) {
    stageShareIntent(intent)
  }

  @Command
  fun pickTree(invoke: Invoke) {
    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
      addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or
        Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
    }
    startActivityForResult(invoke, intent, "pickTreeResult")
  }

  @ActivityCallback
  fun pickTreeResult(invoke: Invoke, result: ActivityResult) {
    val uri = result.data?.data
    if (result.resultCode != Activity.RESULT_OK || uri == null) {
      invoke.resolveObject(mapOf("cancelled" to true))
      return
    }
    val flags = result.data?.flags ?: 0
    val persistable = flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    try { activity.contentResolver.takePersistableUriPermission(uri, persistable) }
    catch (e: Exception) { invoke.reject("Could not retain folder access: ${e.message}"); return }
    invoke.resolveObject(mapOf("uri" to uri.toString(), "cancelled" to false))
  }

  @Command
  fun grantedTrees(invoke: Invoke) {
    runIo(invoke, "Cannot read SAF permissions") {
      activity.contentResolver.persistedUriPermissions.mapNotNull { grant ->
        val uri = grant.uri
        if ((!grant.isReadPermission && !grant.isWritePermission) || !DocumentsContract.isTreeUri(uri)) return@mapNotNull null
        val rootDocument = DocumentsContract.buildDocumentUriUsingTree(uri, DocumentsContract.getTreeDocumentId(uri))
        val label = queryDisplayName(rootDocument) ?: uri.lastPathSegment ?: "Shared folder"
        mapOf("path" to uri.toString(), "label" to "$label (SAF)", "kind" to "saf_tree", "read_only" to !grant.isWritePermission)
      }
    }
  }

  @Command
  fun listTree(invoke: Invoke) {
    val uri = invoke.parseArgs(TreeArgs::class.java).uri
    runIo(invoke, "Cannot list SAF folder") { listChildren(Uri.parse(uri)) }
  }

  @Command
  fun statUri(invoke: Invoke) {
    val uri = Uri.parse(invoke.parseArgs(SingleUriArgs::class.java).uri)
    runIo(invoke, "Cannot read SAF document") { readEntry(resolveDocument(uri)) }
  }

  @Command
  fun readUri(invoke: Invoke) {
    val uri = Uri.parse(invoke.parseArgs(SingleUriArgs::class.java).uri)
    val resolved = resolveDocument(uri)
    runIo(invoke, "Cannot read SAF document") {
      val bytes = activity.contentResolver.openInputStream(resolved)?.use { it.readBytes() }
        ?: throw IllegalStateException("provider returned no stream")
      mapOf("base64" to android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP))
    }
  }

  @Command
  fun writeUri(invoke: Invoke) {
    val args = invoke.parseArgs(WriteArgs::class.java)
    runIo(invoke, "Cannot write SAF document") {
      val parent = resolveDocument(Uri.parse(args.parent_uri))
      val existing = findChild(parent, args.name)
      if (existing != null && readEntry(existing)["is_dir"] == true) {
        throw IllegalStateException("a folder already has that name")
      }
      val target = existing ?: DocumentsContract.createDocument(activity.contentResolver, parent, "application/octet-stream", args.name)
        ?: throw IllegalStateException("provider did not create the document")
      val bytes = android.util.Base64.decode(args.data_base64, android.util.Base64.DEFAULT)
      activity.contentResolver.openOutputStream(target, "wt")?.use { it.write(bytes); it.flush() }
        ?: throw IllegalStateException("provider returned no output stream")
      mapOf("uri" to target.toString())
    }
  }

  @Command
  fun mkdirUri(invoke: Invoke) {
    val args = invoke.parseArgs(NameArgs::class.java)
    runIo(invoke, "Cannot create SAF folder") {
      val parent = resolveDocument(Uri.parse(args.parent_uri))
      val existing = findChild(parent, args.name)
      val result = if (existing != null) {
        if (readEntry(existing)["is_dir"] != true) throw IllegalStateException("an item already has that name")
        existing
      } else {
        DocumentsContract.createDocument(activity.contentResolver, parent, DocumentsContract.Document.MIME_TYPE_DIR, args.name)
          ?: throw IllegalStateException("provider did not create the directory")
      }
      mapOf("uri" to result.toString())
    }
  }

  @Command
  fun deleteUri(invoke: Invoke) {
    val uri = Uri.parse(invoke.parseArgs(SingleUriArgs::class.java).uri)
    runIo(invoke, "Cannot delete SAF document") {
      if (!DocumentsContract.deleteDocument(activity.contentResolver, resolveDocument(uri))) {
        throw IllegalStateException("provider refused deletion")
      }
      mapOf("success" to true)
    }
  }

  @Command
  fun renameUri(invoke: Invoke) {
    val args = invoke.parseArgs(RenameArgs::class.java)
    runIo(invoke, "Cannot rename SAF document") {
      val result = DocumentsContract.renameDocument(activity.contentResolver, resolveDocument(Uri.parse(args.uri)), args.new_name)
        ?: throw IllegalStateException("provider refused rename")
      mapOf("uri" to result.toString())
    }
  }

  @Command
  fun openExternalUri(invoke: Invoke) {
    val raw = invoke.parseArgs(SingleUriArgs::class.java).uri
    val uri = Uri.parse(raw)
    val allowedSchemes = setOf("http", "https", "rdp", "vnc", "spice")
    val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: ""
    val hasUserInfo = uri.encodedAuthority?.contains('@') == true
    if (scheme !in allowedSchemes || hasUserInfo || uri.host.isNullOrBlank()) {
      invoke.reject("External URI is invalid or uses an unsupported scheme")
      return
    }
    activity.runOnUiThread {
      try {
        activity.startActivity(Intent(Intent.ACTION_VIEW, uri))
        invoke.resolveObject(mapOf("opened" to true))
      } catch (e: Exception) {
        invoke.reject("No Android app can open this URI: ${e.message}")
      }
    }
  }

  @Command
  fun stageUris(invoke: Invoke) {
    val uris = invoke.parseArgs(UriArgs::class.java).uris
    runIo(invoke, "Cannot stage shared files") { mapOf("paths" to stageUris(uris)) }
  }

  @Command
  fun takePendingShares(invoke: Invoke) {
    val paths = synchronized(shareLock) { pendingShares.toList().also { pendingShares.clear() } }
    invoke.resolveObject(mapOf("paths" to paths))
  }

  @Command
  fun foregroundStart(invoke: Invoke) {
    val args = invoke.parseArgs(ForegroundStartArgs::class.java)
    try {
      if (Build.VERSION.SDK_INT >= 33 && activity.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
        activity.requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 7302)
      }
      val intent = Intent(activity, LinSCPTransferService::class.java).apply {
        action = LinSCPTransferService.ACTION_START
        putExtra("title", args.title)
        putExtra("ongoing", args.ongoing)
      }
      if (Build.VERSION.SDK_INT >= 26) ContextCompat.startForegroundService(activity, intent) else activity.startService(intent)
      running.set(true)
      invoke.resolveObject(mapOf("running" to true))
    } catch (e: Exception) { invoke.reject("Cannot start transfer service: ${e.message}") }
  }

  @Command
  fun foregroundUpdate(invoke: Invoke) {
    val args = invoke.parseArgs(ProgressArgs::class.java)
    ContextCompat.startForegroundService(activity, Intent(activity, LinSCPTransferService::class.java).apply {
      action = LinSCPTransferService.ACTION_UPDATE
      putExtra("done", args.done); putExtra("total", args.total)
    })
    invoke.resolveObject(mapOf("success" to true))
  }

  @Command
  fun foregroundStop(invoke: Invoke) {
    activity.stopService(Intent(activity, LinSCPTransferService::class.java))
    running.set(false)
    invoke.resolveObject(mapOf("running" to false))
  }

  @Command
  fun foregroundIsRunning(invoke: Invoke) { invoke.resolveObject(mapOf("running" to running.get())) }

  private fun stageShareIntent(intent: Intent) {
    if (intent.action != Intent.ACTION_SEND && intent.action != Intent.ACTION_SEND_MULTIPLE) return
    val uris = linkedSetOf<Uri>()
    intent.data?.let(uris::add)
    intent.clipData?.let { clip -> for (i in 0 until clip.itemCount) clip.getItemAt(i).uri?.let(uris::add) }
    when (intent.action) {
      Intent.ACTION_SEND -> {
        val single: Uri? = if (Build.VERSION.SDK_INT >= 33) {
          intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
          @Suppress("DEPRECATION")
          intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }
        single?.let(uris::add)
      }
      Intent.ACTION_SEND_MULTIPLE -> {
        @Suppress("DEPRECATION")
        val extras = intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
        extras?.forEach(uris::add)
      }
    }
    if (uris.isEmpty()) return
    Thread({
      try {
        val files = stageUris(uris.map(Uri::toString))
        synchronized(shareLock) { pendingShares.addAll(files) }
      } catch (_: Exception) { /* Invalid or inaccessible share URIs are not queued. */ }
    }, "linscp-incoming-share").start()
  }

  private fun stageUris(uris: List<String>): List<String> = synchronized(stageLock) {
    if (uris.size > 100) throw IllegalStateException("a maximum of 100 shared items is supported")
    if (!shareDir.exists() && !shareDir.mkdirs()) throw IllegalStateException("cannot create private staging directory")
    shareDir.listFiles()?.filter { System.currentTimeMillis() - it.lastModified() > 3L * 24 * 60 * 60 * 1000 }?.forEach { it.deleteRecursively() }
    val staged = mutableListOf<String>()
    var totalBytes = 0L
    for (raw in uris) {
      val uri = Uri.parse(raw)
      if (uri.scheme != "content") continue
      val candidate = queryDisplayName(uri)?.replace(Regex("[^A-Za-z0-9._ -]"), "_")?.take(100)?.trim()
      val name = candidate?.takeUnless { it.isBlank() || it == "." || it == ".." } ?: "shared-file"
      val batch = File(shareDir, UUID.randomUUID().toString())
      if (!batch.mkdirs()) throw IllegalStateException("cannot create private staging directory")
      val file = File(batch, name)
      try {
        activity.contentResolver.openInputStream(uri)?.use { input ->
          FileOutputStream(file).use { output ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
              val count = input.read(buffer)
              if (count < 0) break
              totalBytes += count
              if (totalBytes > maxSharedBytes) throw IllegalStateException("shared files exceed the 512 MiB limit")
              output.write(buffer, 0, count)
            }
            output.fd.sync()
          }
        } ?: throw IllegalStateException("cannot open $uri")
      } catch (e: Exception) {
        file.delete()
        staged.forEach { File(it).delete() }
        throw e
      }
      file.setReadable(false, false); file.setWritable(false, false)
      file.setReadable(true, true); file.setWritable(true, true)
      staged.add(file.absolutePath)
    }
    staged
  }

  private fun treeUri(uri: Uri): Uri {
    // Child document URIs also contain the `/tree/<grant-id>/` segments. Keep
    // that original grant id rather than accidentally treating the child id as
    // a new tree root.
    val segments = uri.pathSegments
    val treeIndex = segments.indexOf("tree")
    if (treeIndex >= 0 && treeIndex + 1 < segments.size) {
      return DocumentsContract.buildTreeDocumentUri(uri.authority, segments[treeIndex + 1])
    }
    if (DocumentsContract.isTreeUri(uri)) return uri
    return DocumentsContract.buildTreeDocumentUri(uri.authority, DocumentsContract.getDocumentId(uri))
  }
  private fun documentUri(uri: Uri): Uri {
    // A child URI produced by buildDocumentUriUsingTree already identifies its
    // document even though it also contains the tree grant segment.
    if (uri.pathSegments.contains("document")) return uri
    if (!DocumentsContract.isTreeUri(uri)) return uri
    return DocumentsContract.buildDocumentUriUsingTree(uri, DocumentsContract.getTreeDocumentId(uri))
  }

  /**
   * Resolves the segments below a tree to a document URI the provider accepts.
   *
   * The rest of the application builds child URIs as `.../document/<name>`,
   * because on shared storage the document id *is* the name (`primary:Download`
   * and `primary:Download/report.pdf`). Google Drive, and any provider that
   * keeps an opaque id, hands out something like `1a2B3c...` instead, so a URI
   * carrying the display name names a document that does not exist and the
   * provider refuses it. Every command below therefore resolves a name against
   * the provider's own child listing before it builds a URI.
   *
   * A segment that already matches a document id is used as it stands, which
   * keeps the shared-storage form - and every path the page builds after
   * listing a folder through this plugin - working unchanged.
   */
  private fun resolveDocument(uri: Uri): Uri {
    if (!DocumentsContract.isTreeUri(uri)) return uri
    val segments = uri.pathSegments
    val treeIndex = segments.indexOf("tree")
    val childIndex = segments.indexOf("document")
    // The tree itself, or a URI that already names one document by id.
    if (treeIndex < 0 || treeIndex + 1 >= segments.size || childIndex < 0) return documentUri(uri)
    val grantId = segments[treeIndex + 1]
    var current = DocumentsContract.buildDocumentUriUsingTree(uri, grantId)
    var i = childIndex + 1
    while (i < segments.size) {
      // `document/id/document/id/...` - the pairs repeat, so skip the keyword.
      if (segments[i] == "document") { i += 1; continue }
      val wanted = segments[i]
      val children = DocumentsContract.buildChildDocumentsUriUsingTree(
        uri, DocumentsContract.getDocumentId(current))
      var found: String? = null
      activity.contentResolver.query(
        children,
        arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME),
        null, null, null)?.use { cursor ->
        val idColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
        val nameColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
        while (cursor.moveToNext()) {
          val id = cursor.getString(idColumn) ?: continue
          // An id that matches exactly is the shared-storage shape and wins;
          // otherwise the display name is what the caller meant.
          if (id == wanted) { found = id; break }
          if (cursor.getString(nameColumn) == wanted && found == null) found = id
        }
      } ?: throw IllegalStateException("provider returned no directory listing")
      val id = found ?: throw IllegalStateException("no document named $wanted in this folder")
      current = DocumentsContract.buildDocumentUriUsingTree(uri, id)
      i += 1
    }
    return current
  }
  private fun listChildren(uri: Uri): List<Map<String, Any>> {
    val tree = treeUri(uri)
    val parent = resolveDocument(uri)
    val parentId = DocumentsContract.getDocumentId(parent)
    val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentId)
    val out = mutableListOf<Map<String, Any>>()
    activity.contentResolver.query(children, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID), null, null, null)?.use { cursor ->
      val idCol = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
      while (cursor.moveToNext()) {
        val child = DocumentsContract.buildDocumentUriUsingTree(tree, cursor.getString(idCol))
        try { out.add(readEntry(child)) } catch (_: Exception) { }
      }
    } ?: throw IllegalStateException("provider returned no directory listing")
    return out.sortedBy { it["name"].toString() }
  }
  private fun readEntry(uri: Uri): Map<String, Any> {
    val doc = documentUri(uri)
    var name = doc.lastPathSegment ?: "document"
    var size = 0L; var dir = false; var mtime = 0L
    activity.contentResolver.query(doc, arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME, DocumentsContract.Document.COLUMN_SIZE, DocumentsContract.Document.COLUMN_MIME_TYPE, DocumentsContract.Document.COLUMN_LAST_MODIFIED), null, null, null)?.use { cursor ->
      if (cursor.moveToFirst()) {
        name = cursor.getString(0) ?: name
        if (!cursor.isNull(1)) size = cursor.getLong(1)
        dir = cursor.getString(2) == DocumentsContract.Document.MIME_TYPE_DIR
        if (!cursor.isNull(3)) mtime = cursor.getLong(3) / 1000
      }
    } ?: throw IllegalStateException("provider returned no metadata")
    val date = if (mtime > 0) SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(mtime * 1000)) else ""
    return mapOf("name" to name, "size" to size, "is_dir" to dir, "is_symlink" to false, "broken_link" to false, "date" to date, "mtime" to mtime, "permissions" to "", "owner" to "", "group" to "")
  }
  private fun findChild(parent: Uri, name: String): Uri? {
    val tree = treeUri(parent)
    val parentDoc = documentUri(parent)
    val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, DocumentsContract.getDocumentId(parentDoc))
    activity.contentResolver.query(children, arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME), null, null, null)?.use { cursor ->
      val idColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
      val nameColumn = cursor.getColumnIndexOrThrow(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
      while (cursor.moveToNext()) {
        if (cursor.getString(nameColumn) == name) {
          return DocumentsContract.buildDocumentUriUsingTree(tree, cursor.getString(idColumn))
        }
      }
    } ?: throw IllegalStateException("provider returned no directory listing")
    return null
  }
  private fun queryDisplayName(uri: Uri): String? = activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
}

class LinSCPTransferService : Service() {
  private val channelId = "linscp-transfers"
  private var foreground = false
  private var activeTitle = "LinSCP transfers"
  override fun onCreate() { super.onCreate(); createChannel() }
  override fun onBind(intent: Intent?): IBinder? = null
  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_START -> {
        activeTitle = intent.getStringExtra("title") ?: "LinSCP transfers"
        val count = intent.getIntExtra("ongoing", 0)
        startForeground(NOTIFICATION_ID, notification(activeTitle, count, 0, 0))
        foreground = true
      }
      ACTION_UPDATE -> {
        val done = intent.getLongExtra("done", 0); val total = intent.getLongExtra("total", 0)
        if (!foreground) {
          startForeground(NOTIFICATION_ID, notification(activeTitle, 1, done, total))
          foreground = true
        } else {
          (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION_ID, notification(activeTitle, 1, done, total))
        }
      }
      ACTION_STOP -> { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() }
    }
    return START_NOT_STICKY
  }
  private fun createChannel() {
    if (Build.VERSION.SDK_INT >= 26) {
      (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(NotificationChannel(channelId, "File transfers", NotificationManager.IMPORTANCE_LOW))
    }
  }
  private fun notification(title: String, count: Int, done: Long, total: Long): Notification {
    val builder = NotificationCompat.Builder(this, channelId).setSmallIcon(android.R.drawable.stat_sys_upload).setContentTitle(title).setContentText(if (total > 0) "${done / 1024} KiB of ${total / 1024} KiB" else "$count active transfer(s)").setOngoing(true).setOnlyAlertOnce(true)
    if (total > 0) builder.setProgress(100, ((done.coerceAtMost(total) * 100) / total).toInt(), false) else builder.setProgress(0, 0, true)
    return builder.build()
  }
  companion object {
    const val ACTION_START = "com.fairuniversal.linscp.TRANSFER_START"
    const val ACTION_UPDATE = "com.fairuniversal.linscp.TRANSFER_UPDATE"
    const val ACTION_STOP = "com.fairuniversal.linscp.TRANSFER_STOP"
    const val NOTIFICATION_ID = 7301
  }
}
