package com.fairuniversal.linscp

import android.app.Activity
import android.content.Intent
import android.content.ClipData
import android.content.ClipboardManager
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
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import android.webkit.MimeTypeMap
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
internal class KeystoreBlobArgs { lateinit var data_base64: String }
@InvokeArg
internal class ClipboardTextArgs { var text: String = "" }

@InvokeArg
internal class TreeArgs { lateinit var uri: String }
@InvokeArg
internal class UriArgs { lateinit var uris: ArrayList<String> }
@InvokeArg
internal class SingleUriArgs { lateinit var uri: String }
@InvokeArg
internal class ReadChunkArgs { lateinit var uri: String; var offset: Long = 0; var length: Int = 1048576 }
@InvokeArg
internal class WriteArgs { lateinit var parent_uri: String; lateinit var name: String; lateinit var data_base64: String }
@InvokeArg
internal class AppendChunkArgs { lateinit var uri: String; lateinit var data_base64: String }
@InvokeArg
internal class NameArgs { lateinit var parent_uri: String; lateinit var name: String }
@InvokeArg
internal class RenameArgs { lateinit var uri: String; lateinit var new_name: String }
@InvokeArg
internal class ForegroundStartArgs { lateinit var title: String; var ongoing: Int = 0 }
@InvokeArg
internal class ProgressArgs { var done: Long = 0; var total: Long = 0 }
@InvokeArg
internal class ExportArgs { lateinit var batch: String; lateinit var names: ArrayList<String> }
@InvokeArg
internal class LocalExportArgs { lateinit var batch: String; lateinit var directory: String; lateinit var names: ArrayList<String> }
@InvokeArg
internal class ExportBatchArgs { lateinit var batch: String }

/**
 * Hides Android's system navigation bar while LinSCP is active so the bottom
 * panel switcher, selection bar and terminal extra-key row have the bottom edge
 * to themselves; an edge swipe transiently reveals the system bar on demand.
 */
internal fun hideAndroidNavigationBar(activity: Activity) {
  val window = activity.window ?: return
  val decorView = window.decorView ?: return
  val applyHide = Runnable {
    val currentWindow = activity.window ?: return@Runnable
    val currentDecor = currentWindow.decorView ?: return@Runnable
    val controller = WindowCompat.getInsetsController(currentWindow, currentDecor)
    controller.systemBarsBehavior =
      WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
    controller.hide(WindowInsetsCompat.Type.navigationBars())
  }
  applyHide.run()
  decorView.post(applyHide)
}

/** A distinct provider avoids merging another plugin's FileProvider settings. */
class LinSCPExportProvider : FileProvider()

/** Android implementation behind the Rust `linscp-platform::android` bridges. */
@TauriPlugin
class LinSCPAndroidPlugin(private val activity: Activity) : Plugin(activity) {
  private val running = AtomicBoolean(false)
  private val notificationPermissionAsked = AtomicBoolean(false)
  private val shareLock = Any()
  private val pendingShares = mutableListOf<String>()
  private val shareDir: File get() = File(activity.cacheDir, "incoming-shares")
  private val maxSharedBytes = 512L * 1024L * 1024L
  private val stageLock = Any()
  private val exportLock = Any()
  private val activeExports = mutableSetOf<String>()
  private val exportRoot: File get() = File(activity.cacheDir, "outgoing-shares")
  private val exportLimit = 512L * 1024L * 1024L
  private val exportLifetime = 24L * 60 * 60 * 1000

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
    activity.runOnUiThread {
      webView.settings.domStorageEnabled = true
      hideAndroidNavigationBar(activity)
      installNavigationBarInsetsGuard(webView)
    }
    Thread({ cleanupOldExports() }, "linscp-export-cleanup").start()
    activity.intent?.let { stageShareIntent(it) }
  }

  private fun installNavigationBarInsetsGuard(webView: WebView) {
    var wasImeVisible = false
    ViewCompat.setOnApplyWindowInsetsListener(webView) { view, insets ->
      val imeVisible = insets.isVisible(WindowInsetsCompat.Type.ime())
      if (wasImeVisible && !imeVisible) {
        view.post { hideAndroidNavigationBar(activity) }
      }
      wasImeVisible = imeVisible
      ViewCompat.onApplyWindowInsets(view, insets)
    }
    webView.viewTreeObserver?.addOnWindowFocusChangeListener { hasFocus ->
      if (hasFocus) {
        hideAndroidNavigationBar(activity)
      }
    }
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
  fun readUriChunk(invoke: Invoke) {
    val args = invoke.parseArgs(ReadChunkArgs::class.java)
    val resolved = resolveDocument(Uri.parse(args.uri))
    val want = args.length.coerceIn(0, 4 * 1024 * 1024)
    val offset = args.offset.coerceAtLeast(0L)
    runIo(invoke, "Cannot read SAF document chunk") {
      if (want == 0) return@runIo mapOf("base64" to "")
      val buf = ByteArray(want)
      var totalRead = 0
      val pfd = try { activity.contentResolver.openFileDescriptor(resolved, "r") } catch (_: Exception) { null }
      if (pfd != null) {
        pfd.use { fd ->
          java.io.FileInputStream(fd.fileDescriptor).use { fis ->
            fis.channel.position(offset)
            while (totalRead < want) {
              val n = fis.read(buf, totalRead, want - totalRead)
              if (n <= 0) break
              totalRead += n
            }
          }
        }
      } else {
        activity.contentResolver.openInputStream(resolved)?.use { stream ->
          var remaining = offset
          while (remaining > 0) {
            val skipped = stream.skip(remaining)
            if (skipped <= 0) {
              if (stream.read() < 0) break
              remaining -= 1
            } else {
              remaining -= skipped
            }
          }
          if (remaining == 0L) {
            while (totalRead < want) {
              val n = stream.read(buf, totalRead, want - totalRead)
              if (n <= 0) break
              totalRead += n
            }
          }
        } ?: throw IllegalStateException("provider returned no stream")
      }
      val slice = if (totalRead == buf.size) buf else buf.copyOf(totalRead)
      mapOf("base64" to android.util.Base64.encodeToString(slice, android.util.Base64.NO_WRAP))
    }
  }

  @Command
  fun beginWriteUri(invoke: Invoke) {
    val args = invoke.parseArgs(NameArgs::class.java)
    runIo(invoke, "Cannot create SAF document") {
      val parent = resolveDocument(Uri.parse(args.parent_uri))
      val existing = findChild(parent, args.name)
      if (existing != null && readEntry(existing)["is_dir"] == true) {
        throw IllegalStateException("a folder already has that name")
      }
      val target = existing ?: DocumentsContract.createDocument(activity.contentResolver, parent, "application/octet-stream", args.name)
        ?: throw IllegalStateException("provider did not create the document")
      activity.contentResolver.openOutputStream(target, "wt")?.close()
        ?: throw IllegalStateException("provider returned no output stream")
      mapOf("uri" to target.toString())
    }
  }

  @Command
  fun appendUriChunk(invoke: Invoke) {
    val args = invoke.parseArgs(AppendChunkArgs::class.java)
    runIo(invoke, "Cannot append SAF document chunk") {
      val target = resolveDocument(Uri.parse(args.uri))
      val bytes = android.util.Base64.decode(args.data_base64, android.util.Base64.DEFAULT)
      if (bytes.isNotEmpty()) {
        val appended = try {
          activity.contentResolver.openOutputStream(target, "wa")?.use { out ->
            out.write(bytes)
            out.flush()
            true
          } ?: false
        } catch (_: Exception) {
          false
        }
        if (!appended) {
          val pfd = activity.contentResolver.openFileDescriptor(target, "rw")
            ?: throw IllegalStateException("provider returned no writable descriptor")
          pfd.use { fd ->
            java.io.FileOutputStream(fd.fileDescriptor).use { fos ->
              fos.channel.position(fos.channel.size())
              fos.write(bytes)
              fos.flush()
            }
          }
        }
      }
      mapOf("ok" to true)
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

  // Export batches are private until FileProvider grants an exact URI to the
  // receiving app. They are kept after the chooser returns because a receiver
  // may read asynchronously; old inactive batches are removed opportunistically.
  private fun cleanupOldExports() = synchronized(exportLock) {
    val cutoff = System.currentTimeMillis() - exportLifetime
    exportRoot.listFiles()?.forEach { batch ->
      if (batch.absolutePath !in activeExports && batch.lastModified() < cutoff) batch.deleteRecursively()
    }
  }

  private fun activeExport(path: String): File = synchronized(exportLock) {
    val root = exportRoot.canonicalFile
    val batch = File(path)
    if (batch.absolutePath !in activeExports || batch.canonicalFile.parentFile != root || !batch.isDirectory)
      throw IllegalStateException("invalid or expired share batch")
    batch
  }

  private fun checkedExportNames(names: List<String>) {
    if (names.isEmpty() || names.size > 32 || names.toSet().size != names.size)
      throw IllegalStateException("select between 1 and 32 distinct files")
    for (name in names) {
      if (name.isEmpty() || name == "." || name == ".." || name.any { it == '/' || it == '\\' || it == ':' || it.isISOControl() })
        throw IllegalStateException("invalid file name")
    }
  }

  @Command
  fun prepareExport(invoke: Invoke) {
    runIo(invoke, "Cannot prepare sharing") {
      synchronized(exportLock) {
        cleanupOldExports()
        if (!exportRoot.exists() && !exportRoot.mkdirs()) throw IllegalStateException("cannot create private cache")
        val batch = File(exportRoot, UUID.randomUUID().toString())
        if (!batch.mkdir()) throw IllegalStateException("cannot create private share batch")
        activeExports.add(batch.absolutePath)
        mapOf("path" to batch.absolutePath)
      }
    }
  }

  @Command
  fun stageLocalExport(invoke: Invoke) {
    val args = invoke.parseArgs(LocalExportArgs::class.java)
    runIo(invoke, "Cannot prepare local files for sharing") {
      checkedExportNames(args.names)
      val batch = activeExport(args.batch)
      var total = 0L
      for (name in args.names) {
        val input = if (args.directory.startsWith("content://")) {
          val uri = Uri.parse(args.directory).buildUpon().appendPath("document").appendPath(name).build()
          val resolved = resolveDocument(uri)
          if (readEntry(resolved)["is_dir"] == true) throw IllegalStateException("only files can be shared")
          activity.contentResolver.openInputStream(resolved) ?: throw IllegalStateException("cannot read selected document")
        } else {
          val source = File(args.directory, name)
          val appRoot = File(activity.applicationInfo.dataDir).canonicalFile
          val canonical = source.canonicalFile
          if (!canonical.toPath().startsWith(appRoot.toPath()) || !source.isFile || java.nio.file.Files.isSymbolicLink(source.toPath()))
            throw IllegalStateException("only regular files in app storage can be shared")
          source.inputStream()
        }
        input.use { src ->
          val dest = File(batch, name)
          if (!dest.createNewFile()) throw IllegalStateException("share destination already exists")
          FileOutputStream(dest).use { out ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
              val count = src.read(buffer)
              if (count < 0) break
              total += count
              if (total > exportLimit) throw IllegalStateException("shared files exceed the 512 MiB limit")
              out.write(buffer, 0, count)
            }
            out.fd.sync()
          }
        }
      }
      mapOf("success" to true)
    }
  }

  @Command
  fun discardExport(invoke: Invoke) {
    val args = invoke.parseArgs(ExportBatchArgs::class.java)
    runIo(invoke, "Cannot clean up share") {
      synchronized(exportLock) {
        val batch = activeExport(args.batch)
        batch.deleteRecursively()
        activeExports.remove(batch.absolutePath)
      }
      mapOf("success" to true)
    }
  }

  @Command
  fun openExport(invoke: Invoke) {
    val args = invoke.parseArgs(ExportArgs::class.java)
    try {
      checkedExportNames(args.names)
      val batch = activeExport(args.batch)
      val files = args.names.map { name ->
        val file = File(batch, name)
        if (!file.isFile || java.nio.file.Files.isSymbolicLink(file.toPath()) || file.canonicalFile.parentFile != batch.canonicalFile)
          throw IllegalStateException("a staged file is missing or invalid")
        file
      }
      if (files.sumOf { it.length() } > exportLimit) throw IllegalStateException("shared files exceed the 512 MiB limit")
      val uris = files.map { FileProvider.getUriForFile(activity, activity.packageName + ".outgoing", it) }
      val types = files.map { file ->
        MimeTypeMap.getSingleton().getMimeTypeFromExtension(file.extension.lowercase(Locale.ROOT)) ?: "application/octet-stream"
      }
      val mime = if (types.distinct().size == 1) types.first() else "*/*"
      val clip = ClipData.newRawUri("LinSCP", uris.first())
      uris.drop(1).forEach { clip.addItem(ClipData.Item(it)) }
      val send = Intent(if (uris.size == 1) Intent.ACTION_SEND else Intent.ACTION_SEND_MULTIPLE).apply {
        type = mime
        if (uris.size == 1) putExtra(Intent.EXTRA_STREAM, uris.first())
        else putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
        clipData = clip
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      }
      activity.runOnUiThread {
        try {
          val chooser = Intent.createChooser(send, null).apply {
            clipData = clip
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
          }
          activity.startActivity(chooser)
          synchronized(exportLock) { batch.setLastModified(System.currentTimeMillis()); activeExports.remove(batch.absolutePath) }
          invoke.resolveObject(mapOf("success" to true))
        } catch (e: Exception) { invoke.reject("Cannot open share chooser: ${e.message}") }
      }
    } catch (e: Exception) { invoke.reject("Cannot prepare share: ${e.message}") }
  }

  @Command
  fun foregroundStart(invoke: Invoke) {
    val args = invoke.parseArgs(ForegroundStartArgs::class.java)
    try {
      if (Build.VERSION.SDK_INT >= 33 &&
          activity.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED &&
          notificationPermissionAsked.compareAndSet(false, true)) {
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
    if (running.get()) {
      try {
        activity.startService(Intent(activity, LinSCPTransferService::class.java).apply {
          action = LinSCPTransferService.ACTION_UPDATE
          putExtra("done", args.done); putExtra("total", args.total)
        })
      } catch (_: Exception) {
        // Ignore late progress updates if the transfer service already stopped or backgrounded.
      }
    }
    invoke.resolveObject(mapOf("success" to true))
  }

  @Command
  fun foregroundStop(invoke: Invoke) {
    running.set(false)
    try {
      activity.stopService(Intent(activity, LinSCPTransferService::class.java))
    } catch (_: Exception) {}
    invoke.resolveObject(mapOf("running" to false))
  }

  private val keystoreLock = Any()
  private val keystoreAlias = "linscp_master_key_v1"
  private val keystoreAad = "LSCPKST1".toByteArray(Charsets.US_ASCII)

  private fun getOrCreateKeystoreKey(): SecretKey = synchronized(keystoreLock) {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val existing = (ks.getEntry(keystoreAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
    if (existing != null) return existing
    val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val spec = KeyGenParameterSpec.Builder(
      keystoreAlias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .build()
    keyGen.init(spec)
    keyGen.generateKey()
  }

  @Command
  fun keystoreWrap(invoke: Invoke) {
    val args = invoke.parseArgs(KeystoreBlobArgs::class.java)
    runIo(invoke, "Cannot wrap vault key in Android Keystore") {
      val plaintext = android.util.Base64.decode(args.data_base64, android.util.Base64.DEFAULT)
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKeystoreKey())
      cipher.updateAAD(keystoreAad)
      val iv = cipher.iv ?: throw IllegalStateException("Android Keystore cipher omitted IV")
      if (iv.size != 12) throw IllegalStateException("Unexpected Android Keystore GCM IV length")
      val ct = cipher.doFinal(plaintext)
      val out = ByteArray(iv.size + ct.size)
      System.arraycopy(iv, 0, out, 0, iv.size)
      System.arraycopy(ct, 0, out, iv.size, ct.size)
      mapOf("base64" to android.util.Base64.encodeToString(out, android.util.Base64.NO_WRAP))
    }
  }

  @Command
  fun keystoreUnwrap(invoke: Invoke) {
    val args = invoke.parseArgs(KeystoreBlobArgs::class.java)
    runIo(invoke, "Cannot unwrap vault key from Android Keystore") {
      val wrapped = android.util.Base64.decode(args.data_base64, android.util.Base64.DEFAULT)
      if (wrapped.size < 12 + 16) throw IllegalStateException("Corrupted Android Keystore envelope")
      val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
      val secret = (ks.getEntry(keystoreAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
        ?: throw IllegalStateException("Android Keystore master key entry is missing")
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(128, wrapped, 0, 12))
      cipher.updateAAD(keystoreAad)
      val pt = cipher.doFinal(wrapped, 12, wrapped.size - 12)
      mapOf("base64" to android.util.Base64.encodeToString(pt, android.util.Base64.NO_WRAP))
    }
  }

  @Command
  fun foregroundIsRunning(invoke: Invoke) { invoke.resolveObject(mapOf("running" to running.get())) }

  @Command
  fun readClipboard(invoke: Invoke) {
    activity.runOnUiThread {
      try {
        val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clip = cm?.primaryClip
        val text = if (clip != null && clip.itemCount > 0) {
          clip.getItemAt(0)?.coerceToText(activity)?.toString() ?: ""
        } else {
          ""
        }
        invoke.resolveObject(mapOf("text" to text))
      } catch (e: Exception) {
        invoke.reject("Cannot read clipboard: ${e.message}")
      }
    }
  }

  @Command
  fun writeClipboard(invoke: Invoke) {
    val args = invoke.parseArgs(ClipboardTextArgs::class.java)
    activity.runOnUiThread {
      try {
        val cm = activity.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
          ?: throw IllegalStateException("ClipboardManager unavailable")
        cm.setPrimaryClip(ClipData.newPlainText("LinSCP", args.text))
        invoke.resolveObject(mapOf("success" to true))
      } catch (e: Exception) {
        invoke.reject("Cannot write clipboard: ${e.message}")
      }
    }
  }

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
        batch.deleteRecursively()
        staged.forEach { path ->
          val f = File(path)
          f.delete()
          f.parentFile?.takeIf { it.parentFile == shareDir }?.deleteRecursively()
        }
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
    if (!DocumentsContract.isTreeUri(uri)) {
      throw IllegalArgumentException("URI is not inside a granted SAF tree")
    }
    val segments = uri.pathSegments
    val treeIndex = segments.indexOf("tree")
    val childIndex = segments.indexOf("document")
    // The tree itself, or a URI that already names one document by id.
    if (treeIndex < 0 || treeIndex + 1 >= segments.size || childIndex < 0) return documentUri(uri)
    if (segments.size == childIndex + 2) {
      val direct = DocumentsContract.buildDocumentUriUsingTree(uri, segments[childIndex + 1])
      val existsDirectly = try {
        activity.contentResolver.query(
          direct,
          arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID),
          null, null, null
        )?.use { it.moveToFirst() } == true
      } catch (_: Exception) {
        false
      }
      if (existsDirectly) return direct
    }
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
        startServiceForeground(notification(activeTitle, count, 0, 0))
      }
      ACTION_UPDATE -> {
        val done = intent.getLongExtra("done", 0); val total = intent.getLongExtra("total", 0)
        if (!foreground) {
          startServiceForeground(notification(activeTitle, 1, done, total))
        } else {
          (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION_ID, notification(activeTitle, 1, done, total))
        }
      }
      ACTION_STOP -> { foreground = false; stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() }
    }
    return START_NOT_STICKY
  }
  override fun onTimeout(startId: Int) {
    foreground = false
    stopForeground(STOP_FOREGROUND_REMOVE)
    stopSelf(startId)
  }
  override fun onDestroy() { foreground = false; super.onDestroy() }
  private fun startServiceForeground(notification: Notification) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }
    foreground = true
  }
  private fun createChannel() {
    if (Build.VERSION.SDK_INT >= 26) {
      (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).createNotificationChannel(NotificationChannel(channelId, "Background sessions & transfers", NotificationManager.IMPORTANCE_LOW))
    }
  }
  private fun notification(title: String, count: Int, done: Long, total: Long): Notification {
    val isTransfer = total > 0 || count > 1 || title.contains("transfer", ignoreCase = true)
    val subtitle = when {
      total > 0 -> "${done / 1024} KiB of ${total / 1024} KiB"
      isTransfer -> "$count active transfer(s)"
      else -> "Active session kept connected in background"
    }
    val builder = NotificationCompat.Builder(this, channelId)
      .setSmallIcon(if (isTransfer) android.R.drawable.stat_sys_upload else android.R.drawable.stat_notify_sync_noanim)
      .setContentTitle(title)
      .setContentText(subtitle)
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setOngoing(true)
      .setOnlyAlertOnce(true)
    packageManager.getLaunchIntentForPackage(packageName)?.let { launchIntent ->
      launchIntent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
      val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or
        (if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0)
      builder.setContentIntent(PendingIntent.getActivity(this, 0, launchIntent, pendingFlags))
    }
    if (total > 0) {
      builder.setProgress(100, ((done.coerceAtMost(total) * 100) / total).toInt(), false)
    } else if (isTransfer) {
      builder.setProgress(0, 0, true)
    }
    return builder.build()
  }
  companion object {
    const val ACTION_START = "com.fairuniversal.linscp.TRANSFER_START"
    const val ACTION_UPDATE = "com.fairuniversal.linscp.TRANSFER_UPDATE"
    const val ACTION_STOP = "com.fairuniversal.linscp.TRANSFER_STOP"
    const val NOTIFICATION_ID = 7301
  }
}
