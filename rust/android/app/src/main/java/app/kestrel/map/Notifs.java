package app.kestrel.map;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;

/**
 * The notification channel, in one place.
 *
 * <p>Two kinds of notification exist and they are not the same thing:
 *
 * <ul>
 *   <li>the share notification, which must be up for as long as sharing runs and is
 *       owned by {@link ShareService};
 *   <li>ordinary notices, which say something happened and can be dismissed.
 * </ul>
 *
 * <p>Both are here rather than in their callers because a channel's importance is set
 * once, at creation, and setting it twice is confusing rather than helpful: a channel
 * that already exists keeps whatever importance it had.
 */
final class Notifs {
    /** The running share. Low importance: a state, not an alert. */
    private static final String CHANNEL_SHARE = "share";
    /** Ordinary notices. */
    private static final String CHANNEL_NOTICE = "notice";
    private static final int NOTICE_ID = 2;

    private Notifs() {
    }

    /**
     * Build the share notification.
     *
     * <p>Built here and handed back rather than posted: a foreground service has to
     * reach {@code startForeground} within a few seconds or Android kills it, so the
     * channel is created and the notification returned with nothing in between.
     *
     * <p>The Stop action is part of it rather than added by the caller. A user who wants
     * to stop being shared should not have to open the app, and an ongoing notification
     * with no way to act on it is an ongoing notification nobody trusts.
     */
    static Notification share(Context c, String title, String text,
                              PendingIntent open, PendingIntent stop) {
        channel(c, CHANNEL_SHARE, title, NotificationManager.IMPORTANCE_LOW);
        return new Notification.Builder(c, CHANNEL_SHARE)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_mylocation)
                .setOngoing(true)
                .setContentIntent(open)
                .addAction(new Notification.Action.Builder(
                        null, c.getString(R.string.notif_stop), stop).build())
                .build();
    }

    /** Post an ordinary notice. */
    static void post(Context c, String title, String text) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        if (nm == null) {
            // No notification manager: on some heavily locked-down devices this can
            // happen, and there is nowhere to post to. Not worth crashing a share over.
            return;
        }
        channel(c, CHANNEL_NOTICE, title, NotificationManager.IMPORTANCE_DEFAULT);
        nm.notify(NOTICE_ID, new Notification.Builder(c, CHANNEL_NOTICE)
                .setContentTitle(title)
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_map)
                .setAutoCancel(true)
                .build());
    }

    /**
     * Create a channel if it is not there yet.
     *
     * <p>Only ever creates. An existing channel keeps its settings, because the user may
     * have turned it off, and overriding that would be the app deciding its own notice
     * matters more than the user thinks.
     */
    private static void channel(Context c, String id, String name, int importance) {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O) {
            return;
        }
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        if (nm == null || nm.getNotificationChannel(id) != null) {
            return;
        }
        NotificationChannel ch = new NotificationChannel(id, name, importance);
        ch.setShowBadge(false);
        nm.createNotificationChannel(ch);
    }
}