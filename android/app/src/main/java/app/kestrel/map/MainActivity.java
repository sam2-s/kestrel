package app.kestrel.map;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;

import java.util.HashMap;
import java.util.Map;

/**
 * The one activity, and the whole UI surface.
 *
 * <p>This extends {@link android.app.NativeActivity}, which is the platform class that
 * hands a raw window to native code. egui draws every pixel; there is no layout XML, no
 * view hierarchy and no AndroidX anywhere in this app.
 *
 * <p>What this class is left with is the three things native code genuinely cannot do
 * for itself: ask for a runtime permission and be told the answer, start another
 * activity, and keep a reference to itself that the native side can find.
 *
 * <p>The surface is created and destroyed by {@code ANativeActivity}, not here, so there
 * is nothing to wire up in {@code onCreate} beyond telling Rust that the activity
 * exists.
 */
public final class MainActivity extends android.app.NativeActivity {
    /**
     * The activity, while one exists.
     *
     * <p>Cleared in {@code onDestroy}. A static reference to a destroyed activity is
     * the classic Android leak, and every use here checks for null and does nothing
     * rather than touching a dead window.
     */
    private static volatile MainActivity current;

    static final int REQ_LOCATION = 1;
    static final int REQ_BACKGROUND = 2;
    static final int REQ_NOTIFICATIONS = 3;
    static final int REQ_CAMERA = 4;

    /** The scan activity's answer code. */
    private static final int REQ_SCAN = 5;

    /**
     * Permissions already asked for, and whether the platform has since refused.
     *
     * <p>Android offers no way to ask "is this blocked?". The only reliable answer is
     * historical: we asked and no dialog came back. Tracked so the answer is a map
     * lookup and the user is never prompted twice for the same thing.
     */
    private final Map<String, Boolean> blocked = new HashMap<>();

    /** The activity, or null when the app is in the background. */
    static MainActivity current() {
        return current;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        current = this;

        // A share runs in the foreground service and produces a location whether or not
        // anyone is looking at the screen, so the screen is not allowed to sleep while
        // the app is in front. The service keeps sharing either way; this is about the
        // map being readable.
        getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        // The share service may already be running when the activity is created, and
        // the native side needs the current permission state before it draws anything.
        Bridge.reportAll(getApplicationContext());
    }

    @Override
    protected void onResume() {
        super.onResume();
        current = this;
        Bridge.reportBackground(false);
        // Re-read every time the app comes forward: a permission can be revoked from the
        // notification shade or from settings without the app ever being opened, and a
        // map that still claims to be sharing when the permission behind it is gone is
        // the one stale state worth being paranoid about.
        Bridge.reportAll(getApplicationContext());
    }

    @Override
    protected void onPause() {
        Bridge.reportBackground(true);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (current == this) {
            current = null;
        }
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        // Decided in Rust, because only it knows which screen is up: a join screen
        // should close, and the map should leave.
        Bridge.onBackPressed();
    }

    // ------------------------------------------------------------- permissions

    /**
     * Ask for permissions.
     *
     * <p>One request code per group rather than one per call: every answer arrives in a
     * single callback and has to be routed back to the right one.
     */
    void ask(String[] permissions, int requestCode) {
        for (String p : permissions) {
            blocked.remove(p);
        }
        requestPermissions(permissions, requestCode);
    }

    /**
     * Explain, then ask.
     *
     * <p>Only for the permissions whose answer is not obvious — background location and
     * the camera. A dialog before an ordinary permission prompt would be two dialogs
     * back to back, which is how an app teaches people to tap through without reading.
     */
    void explainThen(int message, Runnable action) {
        new android.app.AlertDialog.Builder(this)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok, (d, w) -> action.run())
                .setNegativeButton(R.string.not_now, null)
                .create()
                .show();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (permissions == null || results == null) {
            return;
        }
        for (int i = 0; i < permissions.length && i < results.length; i++) {
            String p = permissions[i];
            if (results[i] == PackageManager.PERMISSION_GRANTED) {
                blocked.remove(p);
            } else {
                blocked.put(p, true);
            }
        }
        // Republished in full, because the derived answers — precise versus approximate
        // — come from two platform permissions at once and cannot be recomputed from a
        // single grant.
        Bridge.reportAll(getApplicationContext());
    }

    /** Whether a permission has been asked for and refused. */
    boolean wasBlocked(String permission) {
        return Boolean.TRUE.equals(blocked.get(permission));
    }

    /** The app's word for a platform permission. */
    static String nameOf(String permission) {
        if (Manifest.permission.ACCESS_FINE_LOCATION.equals(permission)
                || Manifest.permission.ACCESS_COARSE_LOCATION.equals(permission)) {
            return "location";
        }
        if (Manifest.permission.ACCESS_BACKGROUND_LOCATION.equals(permission)) {
            return "background-location";
        }
        if (Manifest.permission.POST_NOTIFICATIONS.equals(permission)) {
            return "notifications";
        }
        if (Manifest.permission.CAMERA.equals(permission)) {
            return "camera";
        }
        return "unknown";
    }

    // ------------------------------------------------------------------ camera

    /**
     * Open the scanner.
     *
     * <p>A separate activity rather than a preview laid over this one. A camera preview
     * wants a surface of its own, and {@code NativeActivity}'s surface is being used
     * by egui; fighting over one window would mean either a flicker on every scan or a
     * second native surface, which is a lot of machinery for reading a QR code. The
     * scan is brief and the map is still there when it ends.
     */
    void beginScan() {
        startActivityForResult(
                new Intent(this, ScanActivity.class), REQ_SCAN);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_SCAN) {
            return;
        }
        if (resultCode != RESULT_OK || data == null) {
            // Cancelled. The scan state machine in Rust settles itself.
            Bridge.reportScan("");
            return;
        }
        String text = data.getStringExtra(ScanActivity.EXTRA_TEXT);
        // The native side decides what the text means. Java does not check whether it is
        // an invitation, so scanning and typing cannot disagree about what counts.
        Bridge.reportScan(text == null ? "" : text);
    }
}
