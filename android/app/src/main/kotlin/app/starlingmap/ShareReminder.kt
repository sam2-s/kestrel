package app.starlingmap

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock

// Inexact either way: a plain alarm may run 75% late, and Android 12 and up stretch a window to 10 minutes.
object ShareReminder {
    const val TAG = "remind"
    private const val MIN_MS = 60_000L
    private const val MAX_MS = 24 * 3_600_000L
    private const val WINDOW_MS = 10 * 60_000L

    private fun pending(ctx: Context): PendingIntent = PendingIntent.getBroadcast(
        ctx,
        5,
        Intent(ctx, ShareReminderReceiver::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    fun schedule(ctx: Context, ms: Long) {
        val am = ctx.getSystemService(AlarmManager::class.java) ?: return
        val delay = ms.coerceIn(MIN_MS, MAX_MS)
        val at = SystemClock.elapsedRealtime() + delay
        runCatching {
            if (delay / 4 * 3 < WINDOW_MS) {
                am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pending(ctx))
            } else {
                am.setWindow(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, WINDOW_MS, pending(ctx))
            }
        }
    }

    // Also takes down a reminder already showing: it is not true once a share runs.
    fun cancel(ctx: Context) {
        runCatching { ctx.getSystemService(AlarmManager::class.java)?.cancel(pending(ctx)) }
        Events.cancel(ctx, TAG)
    }
}

class ShareReminderReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (LocationService.running) return
        Events.postShareOff(context)
    }
}
