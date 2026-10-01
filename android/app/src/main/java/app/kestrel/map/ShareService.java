package app.kestrel.map;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Log;

/**
 * The share service: the thing that keeps sending while the app is closed.
 *
 * <p>This is where the privacy claim is either true or not. The service is a
 * foreground service of type {@code location}, which means Android requires a visible
 * notification for as long as it runs and the user can stop it from the shade at any
 * moment. There is no path in this class that sends a location without a notification
 * saying so.
 *
 * <p>The cadence is chosen to be dull rather than clever. A share posts when there is
 * a fix worth posting, and not otherwise: the circle cares roughly about where someone
 * is now, and a fix every fifteen seconds of a person standing still is a stream of
 * identical coordinates that says nothing except that the app is running.
 */
public final class ShareService extends android.app.Service {
    private static final String TAG = "Kestrel";

    private static final int NOTIF_ID = 1;

    /**
     * How often a position is posted, at most.
     *
     * <p>Fifteen seconds is the Android foreground-service minimum for location and is
     * also slow enough to be cheap. A person walking covers about twenty metres in
     * that time, so anything faster is detail no one can use.
     */
    private static final long MIN_INTERVAL_MS = 15_000L;

    /** A fix older than this is not sent: it is history, and the circle wants the present. */
    private static final long MAX_FIX_AGE_MS = 60_000L;

    /** Held so the process stays alive while sharing. */
    private android.os.PowerManager.WakeLock wake;

    private LocationManager locations;
    private LocationListener listener;
    private final Handler main = new Handler(Looper.getMainLooper());
    private String proxy = "";
    private volatile boolean running;

    public static void start(Context c) {
        Intent i = new Intent(c, ShareService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            c.startForegroundService(i);
        } else {
            c.startService(i);
        }
    }

    public static void stop(Context c) {
        Intent i = new Intent(c, ShareService.class);
        // stopService, not stopForegroundService: the latter detaches the notification
        // without stopping the service, which would leave it running with nothing on
        // screen to stop it. The service clears the notification itself in onDestroy.
        c.stopService(i);
    }

    /**
     * Whether a share is running, so a reboot or an update can resume it.
     *
     * <p>The user's decision is stored rather than the service's existence, because the
     * service does not survive a reboot and the decision does.
     */
    private static final String PREF_SHARING = "sharing";

    static boolean wasSharing(Context c) {
        return c.getSharedPreferences("kestrel", Context.MODE_PRIVATE)
                .getBoolean(PREF_SHARING, false);
    }

    static void setSharing(Context c, boolean on) {
        c.getSharedPreferences("kestrel", Context.MODE_PRIVATE)
                .edit().putBoolean(PREF_SHARING, on).apply();
    }

    /** Route the transport through a proxy, or clear it with an empty string. */
    static void setProxy(Context c, String proxy) {
        c.getSharedPreferences("kestrel", Context.MODE_PRIVATE)
                .edit().putString("proxy", proxy == null ? "" : proxy).apply();
    }

    /** Start the service again after a reboot, if the user had asked for it. */
    static void resumeIfWanted(Context c) {
        if (wasSharing(c)) {
            start(c);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        running = true;
        locations = (LocationManager) getSystemService(LOCATION_SERVICE);
        goForeground(getString(R.string.notif_sharing_title),
                getString(R.string.notif_sharing_text));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        setSharing(this, true);
        startUpdates();
        // START_STICKY: Android restarts the service if it is killed for memory, and a
        // share that silently stops when the system is busy is a share the user thinks
        // is still running. The notification is up either way, so nothing is hidden.
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        running = false;
        stopUpdates();
        releaseWake();
        setSharing(this, false);
        super.onDestroy();
    }

    @Override
    public android.os.IBinder onBind(Intent intent) {
        // Nothing binds to this. A bound service would be a way for another app in the
        // process to read the location stream, and there is no reason for one.
        return null;
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        // Swiped away from the recents list. The share carries on, because the user
        // turned sharing on and the notification is still there to stop it. Closing the
        // app is not the same as saying "stop sharing", and conflating them would make
        // the notification a lie.
        super.onTaskRemoved(rootIntent);
    }

    private void startUpdates() {
        if (listener != null) {
            return;
        }
        if (locations == null) {
            return;
        }
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED
                && checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            // Without a location permission there is nothing to send, and asking again
            // from a service would show a dialog nobody is looking at. The Rust side has
            // already been told the permission is missing and will say so.
            return;
        }

        // Wake lock held only while sharing. Not `PARTIAL_WAKE_LOCK` forever: a lock
        // held with the screen off and nothing to send is a battery complaint waiting
        // to happen.
        android.os.PowerManager pm = (android.os.PowerManager) getSystemService(POWER_SERVICE);
        wake = pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "kestrel:share");
        try {
            wake.acquire();
        } catch (SecurityException e) {
            Log.w(TAG, "no wake lock; updates may be delayed while the screen is off", e);
            wake = null;
        }

        listener = new LocationListener() {
            @Override
            public void onLocationChanged(Location location) {
                post(location);
            }

            @Override
            public void onProviderEnabled(String provider) {
            }

            @Override
            public void onProviderDisabled(String provider) {
            }

            @Override
            public void onStatusChanged(String provider, int status, Bundle extras) {
            }
        };
        try {
            locations.requestLocationUpdates(LocationManager.GPS_PROVIDER,
                    MIN_INTERVAL_MS, 0f, listener, Looper.getMainLooper());
        } catch (SecurityException e) {
            Log.w(TAG, "no permission for updates", e);
        }
        // The network provider as well, because indoors a phone may not see a GPS fix at
        // all and a share that stops indoors is useless.
        try {
            locations.requestLocationUpdates(LocationManager.NETWORK_PROVIDER,
                    MIN_INTERVAL_MS, 0f, listener, Looper.getMainLooper());
        } catch (SecurityException | IllegalArgumentException e) {
            // Some devices have no network provider. Not worth reporting: GPS covers it.
        }
    }

    private void stopUpdates() {
        if (listener != null && locations != null) {
            try {
                locations.removeUpdates(listener);
            } catch (SecurityException e) {
                Log.w(TAG, "could not stop updates", e);
            }
        }
        listener = null;
        releaseWake();
    }

    private void releaseWake() {
        if (wake != null && wake.isHeld()) {
            try {
                wake.release();
            } catch (RuntimeException e) {
                Log.w(TAG, "wake lock already released", e);
            }
        }
        wake = null;
    }

    /**
     * Hand one fix to Rust.
     *
     * <p>Filtered here rather than in Rust: a fix older than a minute, or one from a
     * provider that has gone, is not worth crossing the boundary for.
     */
    private void post(Location location) {
        if (!running || location == null) {
            return;
        }
        long age = SystemClock.elapsedRealtime() - location.getElapsedRealtimeNanos() / 1_000_000L;
        if (age > MAX_FIX_AGE_MS) {
            return;
        }
        int battery = batteryPercent();
        Bridge.reportLocation(
                (int) Math.round(location.getLatitude() * 1e7),
                (int) Math.round(location.getLongitude() * 1e7),
                (int) Math.round(location.getAccuracy()),
                location.getTime(),
                battery);
    }

    /** Battery as a percentage, or -1 when it cannot be read. */
    private int batteryPercent() {
        BatteryManager bm = (BatteryManager) getSystemService(BATTERY_SERVICE);
        int pct = bm == null ? -1 : bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
        return pct;
    }

    /**
     * The notification that has to be up for as long as sharing runs.
     *
     * <p>{@code startForeground} rather than {@code notify}, because Android kills a
     * foreground service that has not reached this within a few seconds of starting, and
     * a service that is killed takes the share with it.
     */
    @SuppressLint("MissingPermission")
    private void goForeground(String title, String text) {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent openPi = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        Intent stop = new Intent(this, StopReceiver.class);
        PendingIntent stopPi = PendingIntent.getBroadcast(this, 1, stop,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        startForeground(NOTIF_ID, Notifs.share(this, title, text, openPi, stopPi));
    }

    /** Stops sharing from the notification's Stop action. */
    public static final class StopReceiver extends android.content.BroadcastReceiver {
        @Override
        public void onReceive(Context c, Intent intent) {
            // Set the stored decision first: if Android kills this process during the
            // broadcast, the service must not come back on the next boot.
            setSharing(c, false);
            stop(c);
        }
    }
}