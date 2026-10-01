package app.kestrel.map;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.WindowManager;
import android.widget.FrameLayout;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * The one activity. Everything is drawn by egui inside a single native surface.
 *
 * <p>This class exists for three things Rust cannot do for itself, and nothing else:
 * asking for permissions and being told the answer, showing the camera, and telling
 * Rust when the app goes to the background. No layout XML, no adapters, no AndroidX —
 * the native surface is the entire UI.
 *
 * <p>A plain {@link android.app.Activity} rather than {@code AppCompatActivity}:
 * there is no AndroidX here, and the only support that mattered was runtime
 * permissions, which {@code android.app.Activity} has had since Android 6.
 */
public final class MainActivity extends android.app.Activity {
    // ------------------------------------------------------ the native surface

    private static native void nativeOnCreate();
    private static native void nativeOnResume();
    private static native void nativeOnPause();
    private static native void nativeOnDestroy();
    private static native void nativeOnBack();
    private static native void nativeOnKey(int keyCode);
    private static native void nativeOnMemoryWarning();
    private static native void nativeSurfaceCreated(SurfaceHolder holder);
    private static native void nativeSurfaceDestroyed();

    /**
     * The one activity per process; this is how Rust finds it.
     *
     * <p>Cleared in {@code onDestroy}, not held. A static reference to a destroyed
     * activity is the classic Android leak, and every caller here checks for null and
     * does nothing rather than touching a dead window.
     */
    private static volatile MainActivity current;

    // ------------------------------------------------- permissions and requests

    static final int REQ_LOCATION = 1;
    static final int REQ_BACKGROUND = 2;
    static final int REQ_NOTIFICATIONS = 3;
    static final int REQ_CAMERA = 4;

    /**
     * Permissions already asked for, and whether the platform has since refused.
     *
     * <p>Android has no way to ask "is this blocked?". The only reliable answer is
     * historical: we asked and no dialog came back. Tracked here so the answer is a map
     * lookup and the user is never prompted twice for the same thing.
     */
    private final Map<String, Boolean> blocked = new HashMap<>();

    // ------------------------------------------------------------ the scanner

    /** The preview, over the map. Null when no scan is running. */
    private static volatile CameraView scanner;

    /** Whether a preview frame is wanted. Set for exactly one frame. */
    private static volatile boolean scanning;

    /** Preview frames waiting for the decoder. Bounded: a queue is not a buffer. */
    private static final BlockingQueue<byte[]> scanFrames = new ArrayBlockingQueue<>(2);

    /** Why the last scan failed, if it did. */
    private static volatile String scanError;

    private FrameLayout root;
    private SurfaceView surface;
    private boolean surfaceReady;

    /** The activity, or null when the app is in the background. */
    static MainActivity current() {
        return current;
    }

    // -------------------------------------------------------------- lifecycle

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        current = this;

        root = new FrameLayout(this);
        surface = new SurfaceView(this);
        root.addView(surface, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        surface.getHolder().addCallback(surfaceCallbacks);
        setContentView(root);

        // A share runs in the foreground service and needs the location it produces to
        // keep running; the screen may be off for much of that.
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        // The share service may already be running when the activity is created, and
        // the Rust side needs the current permission state before it draws anything.
        Bridge.reportAll(getApplicationContext());
        nativeOnCreate();
    }

    @Override
    protected void onResume() {
        super.onResume();
        current = this;
        Bridge.reportBackground(false);
        // The user can change a permission from the notification shade or from settings
        // while the app is closed, so the answer is re-read every time the app comes
        // forward. Reporting it only at startup would let the map claim a share is
        // running when the permission behind it was revoked.
        Bridge.reportAll(getApplicationContext());
        nativeOnResume();
    }

    @Override
    protected void onPause() {
        nativeOnPause();
        Bridge.reportBackground(true);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        nativeOnDestroy();
        // The camera must go before the activity does, or it keeps the hardware and
        // every other app's camera fails.
        endScan();
        if (current == this) {
            current = null;
        }
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        // Rust decides whether this closes a screen or leaves the app, because only it
        // knows which screen is up.
        nativeOnBack();
    }

    @Override
    public boolean onKeyDown(int keyCode, android.view.KeyEvent event) {
        nativeOnKey(keyCode);
        return super.onKeyDown(keyCode, event);
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        // So Rust can shed tile memory before the system kills the process mid-share.
        nativeOnMemoryWarning();
    }

    // --------------------------------------------------------------- permissions

    /**
     * Ask for permissions.
     *
     * <p>One request code per group, not per call: the answer arrives in a single
     * callback and has to be routed back to the right one.
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
     * <p>Only for the permissions whose answer is not obvious — background location
     * and the camera. Two dialogs back to back for the obvious ones would be annoying.
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

    // -------------------------------------------------------------- the scanner

    /** Open the camera to read a code, over the map. */
    void beginScan() {
        if (scanner != null) {
            return;
        }
        scanner = new CameraView(this, new int[]{rotationHint()});
        root.addView(scanner, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT));
        scanner.start();
    }

    /** Take the preview down. Called when a code is read, or the user gives up. */
    void endScan() {
        CameraView v = scanner;
        scanner = null;
        scanning = false;
        if (v != null) {
            v.stop();
            root.removeView(v);
        }
    }

    /**
     * Whether a preview frame is wanted.
     *
     * <p>The decoder asks for one at a time. Decoding every frame of a thirty-frame
     * stream would keep the CPU busy for nothing: a QR code sits still in the frame
     * long enough to be read by one of them.
     */
    static boolean frameWanted() {
        return scanning;
    }

    /** Hand the newest preview frame to the decoder. */
    static void takeFrame(byte[] frame) {
        // Cleared before the hand-off, so two frames are never in flight and the
        // decoder never reads a buffer being overwritten underneath it.
        scanning = false;
        scanFrames.offer(frame);
    }

    /** Tell Rust that a scan could not run. */
    static void scanFailed(String why) {
        scanError = why;
    }

    /** Called from the Rust side when it is ready for another frame. */
    static void wantFrame() {
        scanError = null;
        scanning = true;
    }

    /** Take the next frame, if one arrived. Called from the Rust side. */
    static byte[] nextFrame() {
        byte[] f = scanFrames.poll();
        if (f != null) {
            return f;
        }
        return null;
    }

    /** Take the failure, if there was one. */
    static String takeScanError() {
        String e = scanError;
        scanError = null;
        return e;
    }

    /** How far to rotate the preview so it is the right way up. */
    private int rotationHint() {
        try {
            android.view.Display d = getWindowManager().getDefaultDisplay();
            return d.getRotation() * 90;
        } catch (RuntimeException e) {
            return 0;
        }
    }

    // -------------------------------------------------------- the native surface

    /** Forwards the surface lifecycle to the native view that draws on it. */
    private final SurfaceHolder.Callback surfaceCallbacks = new SurfaceHolder.Callback() {
        @Override
        public void surfaceCreated(SurfaceHolder holder) {
            surfaceReady = true;
            nativeSurfaceCreated(holder);
        }

        @Override
        public void surfaceChanged(SurfaceHolder holder, int format, int width, int height) {
            // The native view is told its size through the surface itself, and a rotation
            // destroys and recreates the surface, which lands in surfaceCreated.
        }

        @Override
        public void surfaceDestroyed(SurfaceHolder holder) {
            surfaceReady = false;
            nativeSurfaceDestroyed();
        }
    };

    /** Whether the native surface has been created. */
    static boolean surfaceIsReady(MainActivity a) {
        return a != null && a.surfaceReady;
    }
}