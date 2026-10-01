package app.kestrel.map;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;

/**
 * The one class Rust talks to.
 *
 * <p>Every method here is called from {@code android.rs} through JNI, and every one
 * of them is static and takes no arguments except strings. That is a deliberate
 * constraint, not an accident of style: the Rust side has a table of JNI signatures
 * and calls through it, so a method that takes a Context, an Activity result or a
 * callback would need its signature kept in step by hand on both sides. Keeping them
 * argument-light means the table is the whole contract.
 *
 * <p>The static methods are called <em>from</em> Rust. The static methods named
 * {@code report*} are called <em>into</em> Rust, and are the native side of the
 * boundary. Nothing else crosses.
 *
 * <p>No instance state, deliberately. There is one activity and one service, both in
 * this process, and the activity is reachable as the application context whenever the
 * app is in the foreground. A static Activity field would be a second thing to keep
 * correct, and it would outlive the activity it pointed at.
 *
 * <p>The library is loaded by {@link MainActivity}, from the manifest's
 * {@code android.app.lib_name}, before {@code onCreate}. That ordering matters: the
 * service calls {@link #reportLocation} from a boot broadcast, long before any activity
 * exists, and it works because the process has already loaded the library by then.
 */
final class Bridge {
    private Bridge() {
    }

    /** The activity, if the app is in the foreground. */
    static MainActivity activity() {
        MainActivity a = MainActivity.current();
        return a != null && !a.isFinishing() ? a : null;
    }

    // ----------------------------------------------- called from Rust

    /**
     * Ask for foreground location.
     *
     * <p>Fine and coarse are requested together because Android 12 lets the user pick
     * coarse only, and the app shares properly at a kilometre rather than refusing to
     * share at all.
     */
    static void requestLocation() {
        MainActivity a = activity();
        if (a == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            a.ask(new String[]{
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION,
            }, MainActivity.REQ_LOCATION);
        } else {
            a.ask(new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, MainActivity.REQ_LOCATION);
        }
    }

    /**
     * Ask for background location, on its own.
     *
     * <p>Android 11 and later ignore a request that bundles background with
     * foreground, so asking together would silently drop the one that matters.
     */
    static void requestBackgroundLocation() {
        MainActivity a = activity();
        if (a == null) {
            return;
        }
        a.explainThen(
                R.string.why_background,
                () -> a.ask(new String[]{
                        Manifest.permission.ACCESS_BACKGROUND_LOCATION,
                }, MainActivity.REQ_BACKGROUND));
    }

    static void requestNotifications() {
        MainActivity a = activity();
        if (a == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            // Below Android 13 the permission does not exist and notifications work
            // without it. Reporting it as granted is the honest answer.
            reportPermission("notifications", "granted");
            return;
        }
        a.ask(new String[]{Manifest.permission.POST_NOTIFICATIONS}, MainActivity.REQ_NOTIFICATIONS);
    }

    static void requestCamera() {
        MainActivity a = activity();
        if (a == null) {
            return;
        }
        a.explainThen(
                R.string.why_camera,
                () -> a.ask(new String[]{Manifest.permission.CAMERA}, MainActivity.REQ_CAMERA));
    }

    /**
     * Send the user to this app's settings page.
     *
     * <p>Used for permissions that cannot be prompted for again.
     */
    static void openAppSettings() {
        Context c = application();
        if (c == null) {
            return;
        }
        Intent i = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                android.net.Uri.fromParts("package", c.getPackageName(), null));
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        c.startActivity(i);
    }

    /**
     * Send the user to the system's location settings, not this app's.
     *
     * <p>Background location lives in the system page, and the app's own page does not
     * have it. Sending someone to the app page to find a switch that is not there is
     * worse than saying plainly where it is.
     */
    static void openLocationSettings() {
        Context c = application();
        if (c == null) {
            return;
        }
        Intent i = new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        c.startActivity(i);
    }

    /** Start the foreground service that shares location. */
    static void startSharing() {
        Context c = application();
        if (c == null) {
            return;
        }
        ShareService.start(c);
    }

    static void stopSharing() {
        Context c = application();
        if (c == null) {
            return;
        }
        ShareService.stop(c);
    }

    /** Open the scanner. */
    static void startScan() {
        MainActivity a = activity();
        if (a == null) {
            return;
        }
        a.beginScan();
    }

    /**
     * The back gesture, decided in Rust.
     *
     * <p>Routed through here because that is the boundary class, and because the
     * activity has no business knowing which screen is up: only the native side does.
     */
    static void onBackPressed() {
        onBackPressedNative();
    }

    private static native void onBackPressedNative();

    /**
     * Post a notification.
     *
     * <p>The only call that is expected to work while the app is closed, which is most
     * of the time a share runs. It goes through the application context rather than
     * the activity so a notification does not depend on a window being open.
     */
    static void notify(String title, String body) {
        Context c = application();
        if (c == null) {
            return;
        }
        Notifs.post(c, title, body);
    }

    /** Route traffic through a proxy. An empty string clears it. */
    static void setProxy(String proxy) {
        Context c = application();
        if (c == null) {
            return;
        }
        ShareService.setProxy(c, proxy);
    }

    // -------------------------------------------------- called into Rust

    /** Tell Rust what the platform says about one permission. */
    static native void reportPermission(String which, String value);

    /**
     * Tell Rust about a location fix.
     *
     * <p>Integers, not doubles: the scale is fixed and the arithmetic on the Rust side
     * is one division. A phone's location is not accurate to the centimetre that a
     * double in degrees would imply.
     */
    static native void reportLocation(int latE7, int lonE7, int accMetres, long tsMillis, int batteryPercent);

    /** Tell Rust what a scanned code says. An empty string means the scan did not work. */
    static native void reportScan(String text);

    // ------------------------------------------------------ the scanner's frames

    /**
     * Preview frames waiting for the decoder.
     *
     * <p>Bounded at two. A queue that grows without limit is a memory leak with a camera
     * pointed at it, and the decoder is slower than the camera: if it cannot keep up,
     * dropping frames is correct and holding them all is not.
     */
    private static final java.util.concurrent.ArrayBlockingQueue<byte[]> frames =
            new java.util.concurrent.ArrayBlockingQueue<>(2);

    /**
     * Whether the decoder wants another frame.
     *
     * <p>Set for exactly one frame at a time. Two frames in flight would mean the decoder
     * reads a buffer that the camera is overwriting underneath it.
     */
    private static volatile boolean wantsFrame;

    /**
     * Hand a preview frame to the decoder.
     *
     * <p>Called from the camera's callback thread, thirty times a second.
     */
    static void pushFrame(byte[] frame) {
        wantsFrame = false;
        frames.offer(frame);
    }

    /** Whether the decoder wants another frame. Read from the camera's thread. */
    static boolean frameWanted() {
        return wantsFrame;
    }

    /**
     * Take the next frame, or null if none has arrived.
     *
     * <p>Called from Rust on the decoding thread, and not declared native. Rust pulls
     * the frame over JNI and decodes it there, so the bytes are copied once. A
     * {@code static native byte[] nextFrame()} would copy them twice: once into the Java
     * array, and once more into whatever Rust builds from it.
     *
     * <p>Clears the request as it goes, so the camera does not queue another frame
     * until this one has been decoded.
     */
    static byte[] nextFrame() {
        wantsFrame = false;
        return frames.poll();
    }

    /** Ask for one more frame, now that the last one has been dealt with. */
    static void wantFrame() {
        wantsFrame = true;
    }

    /** Tell Rust whether the app has gone to the background. */
    static native void reportBackground(boolean inBackground);

    // ------------------------------------------------------------ helpers

    /** The application context, which outlives any window. */
    static Context application() {
        MainActivity a = MainActivity.current();
        return a != null ? a.getApplicationContext() : null;
    }

    /**
     * What to report for a permission right now.
     *
     * <p>Called at startup and whenever the app returns to the foreground, because
     * the answer can change while the app is closed: the user can revoke a permission
     * from the notification shade without ever opening the app.
     */
    static void reportAll(Context c) {
        if (c == null) {
            return;
        }
        reportPermission("location", locationState(c));
        reportPermission("background", backgroundState(c));
        reportPermission("notifications", notificationState(c));
        reportPermission("camera", cameraState(c));
    }

    /**
     * Location, resolved to the words the Rust side reads.
     *
     * <p>The distinction that matters is between {@code "granted"} and
     * {@code "approximate"}: Android reports a coarse grant as granted too, and only
     * the fine one says whether the circle is getting a precise position. Reporting a
     * coarse grant as precise would tell everyone a member's position is exact when it
     * is a kilometre wide.
     */
    private static String locationState(Context c) {
        boolean fine = granted(c, Manifest.permission.ACCESS_FINE_LOCATION);
        boolean coarse = granted(c, Manifest.permission.ACCESS_COARSE_LOCATION);
        if (fine) {
            return "granted";
        }
        if (coarse) {
            return "approximate";
        }
        return deniedState(c, Manifest.permission.ACCESS_FINE_LOCATION);
    }

    /**
     * Background location.
     *
     * <p>Only meaningful once foreground location is held, and on Android 11 and later
     * it is a separate grant that the user makes from settings rather than a dialog.
     */
    private static String backgroundState(Context c) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            // Before Android 10 background came with foreground, so holding location is
            // holding background.
            return granted(c, Manifest.permission.ACCESS_BACKGROUND_LOCATION)
                    ? "granted" : "unavailable";
        }
        if (!granted(c, Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
            // Not yet asked, or refused. Only the dialog's absence tells these apart, so
            // the honest word is "unknown" and the UI can offer to ask.
            return deniedState(c, Manifest.permission.ACCESS_BACKGROUND_LOCATION);
        }
        return "granted";
    }

    private static String notificationState(Context c) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return "granted";
        }
        if (granted(c, Manifest.permission.POST_NOTIFICATIONS)) {
            return "granted";
        }
        return deniedState(c, Manifest.permission.POST_NOTIFICATIONS);
    }

    private static String cameraState(Context c) {
        if (!c.getPackageManager().hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
            // No camera at all, so the app stops asking rather than offering a button
            // that cannot work.
            return "unavailable";
        }
        if (granted(c, Manifest.permission.CAMERA)) {
            return "granted";
        }
        return deniedState(c, Manifest.permission.CAMERA);
    }

    private static boolean granted(Context c, String permission) {
        return c.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Whether a permission is refused for good, or simply refused.
     *
     * <p>The platform has no direct word for this, so the usual test applies: ask
     * again, and if no dialog appears, it is blocked. That is a real prompt on some
     * versions, which is why this runs on a permission the app already asked for and
     * why the answer is only used to decide whether to show a settings link.
     */
    private static String deniedState(Context c, String permission) {
        MainActivity a = activity();
        if (a == null) {
            // Cannot tell from here, so do not claim to know.
            return "unknown";
        }
        return a.wasBlocked(permission) ? "blocked" : "denied";
    }
}