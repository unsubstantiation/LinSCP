package io.linscp.commander

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

/**
 * ForegroundService that holds a PARTIAL_WAKE_LOCK + WIFI_MODE_FULL_HIGH_PERF
 * while transfers or `keepuptodate` watches are active. Prevents Android from
 * suspending WebView and sockets seconds after the screen locks or the user
 * switches apps.
 *
 * Started via `LinScpForegroundService.start(...)` from Rust
 * (`ForegroundServiceBridge::start`) and updates notification progress via
 * `updateProgress`. The notification's Cancel action broadcasts
 * `ACTION_CANCEL_TRANSFERS` which the Rust queue interprets as abort.
 */
class LinScpForegroundService : Service() {

    companion object {
        private const val CHANNEL_ID = "linscp-transfers"
        private const val NOTIF_ID = 0x4C535053 // 'LSPS'
        const val ACTION_CANCEL_TRANSFERS = "io.linscp.commander.CANCEL_TRANSFERS"
        const val EXTRA_TITLE = "title"
        const val EXTRA_ONGOING = "ongoing"

        fun start(context: Context, title: String, ongoingTransfers: Int) {
            val intent = Intent(context, LinScpForegroundService::class.java).apply {
                putExtra(EXTRA_TITLE, title)
                putExtra(EXTRA_ONGOING, ongoingTransfers)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun updateProgress(context: Context, bytesDone: Long, bytesTotal: Long) {
            val intent = Intent(context, LinScpForegroundService::class.java).apply {
                action = "UPDATE_PROGRESS"
                putExtra("done", bytesDone)
                putExtra("total", bytesTotal)
            }
            context.startService(intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, LinScpForegroundService::class.java))
        }
    }

    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var currentTitle: String = "LinSCP transfers"
    private var bytesDone: Long = 0
    private var bytesTotal: Long = 0

    override fun onCreate() {
        super.onCreate()
        createChannel()
        acquireLocks()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "UPDATE_PROGRESS" -> {
                bytesDone = intent.getLongExtra("done", bytesDone)
                bytesTotal = intent.getLongExtra("total", bytesTotal)
                updateNotification()
                return START_STICKY
            }
            ACTION_CANCEL_TRANSFERS -> {
                LinScpTauriPlugin.emitCancelTransfers()
                stopSelf()
                return START_NOT_STICKY
            }
        }
        currentTitle = intent?.getStringExtra(EXTRA_TITLE) ?: currentTitle
        val ongoing = intent?.getIntExtra(EXTRA_ONGOING, 0) ?: 0
        if (ongoing == 0 && bytesTotal == 0L) {
            // Still show generic text until first progress update
        }
        startForeground(NOTIF_ID, buildNotification(currentTitle, ongoing))
        return START_STICKY
    }

    override fun onDestroy() {
        releaseLocks()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.foreground_notification_title),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shows transfer progress while LinSCP runs in background"
                setShowBadge(false)
            }
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun acquireLocks() {
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "LinSCP::TransferWakeLock").apply {
                setReferenceCounted(false)
                acquire(30 * 60 * 1000L) // 30 min timeout; renewed on each start
            }
        } catch (_: Exception) { /* ignore on devices without WAKE_LOCK */ }

        try {
            val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "LinSCP::WifiLock").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (_: Exception) { }
    }

    private fun releaseLocks() {
        try { wakeLock?.let { if (it.isHeld) it.release() } } catch (_: Exception) { }
        try { wifiLock?.let { if (it.isHeld) it.release() } } catch (_: Exception) { }
        wakeLock = null
        wifiLock = null
    }

    private fun buildNotification(title: String, ongoing: Int): Notification {
        val cancelIntent = PendingIntent.getService(
            this, 0,
            Intent(this, LinScpForegroundService::class.java).apply { action = ACTION_CANCEL_TRANSFERS },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val openIntent = packageManager.getLaunchIntentForPackage(packageName)?.let { launch ->
            PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        }

        val progressText = if (bytesTotal > 0) {
            val pct = (bytesDone * 100 / bytesTotal).coerceIn(0, 100)
            "$pct% • ${humanBytes(bytesDone)} / ${humanBytes(bytesTotal)}"
        } else if (ongoing > 0) {
            "$ongoing file(s) • ${getString(R.string.foreground_notification_text, ongoing, "")}".trim()
        } else {
            title
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(progressText)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(NotificationCompat.Action(0, getString(R.string.foreground_notification_cancel), cancelIntent))
            .setProgress(if (bytesTotal > 0) 100 else 0, if (bytesTotal > 0) (bytesDone * 100 / bytesTotal).toInt() else 0, bytesTotal == 0L && ongoing > 0)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun updateNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(currentTitle, 0))
    }

    private fun humanBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> String.format("%.1f KiB", bytes / 1024.0)
        bytes < 1024 * 1024 * 1024 -> String.format("%.1f MiB", bytes / (1024.0 * 1024))
        else -> String.format("%.2f GiB", bytes / (1024.0 * 1024 * 1024))
    }
}
