package app.kestrel.map;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.FrameLayout;

/**
 * A window with a camera in it, for as long as a scan lasts.
 *
 * <p>A plain {@link Activity} with a {@link FrameLayout}, because this is the one place
 * in the app with a conventional layout: a camera preview is a {@link android.view.SurfaceView}
 * and there is nothing interesting to draw around it. Doing this here rather than over
 * the main activity means the map's native surface is never contended with a camera
 * surface, and finishing a scan cannot leave a hole in the UI.
 *
 * <p>The result is handed back through {@code setResult}, not through the native
 * callback. An activity result is the platform's own answer to "what did that window
 * find", and it survives the main activity being recreated in between.
 */
public final class ScanActivity extends Activity {
    static final String EXTRA_TEXT = "text";

    private CameraView camera;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (checkSelfPermission(android.Manifest.permission.CAMERA)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            // Rust has already been told the permission is missing and is offering a
            // settings link; opening a camera here would only produce a black window.
            finish();
            return;
        }

        FrameLayout root = new FrameLayout(this);
        camera = new CameraView(this, rotationHint());
        root.addView(camera, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);
        camera.start();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (camera != null) {
            camera.start();
        }
    }

    @Override
    protected void onPause() {
        // The camera goes away when the window is not in front. Holding it would keep the
        // hardware warm and every other app's camera locked for as long as this sits in
        // the back stack.
        if (camera != null) {
            camera.stop();
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (camera != null) {
            camera.stop();
            camera = null;
        }
        super.onDestroy();
    }

    /**
     * A code was read. Returns it and closes.
     *
     * <p>Called from the native decoder through {@link Bridge}, which is the only path
     * between the two halves.
     */
    void found(String text) {
        Intent i = new Intent();
        i.putExtra(EXTRA_TEXT, text);
        setResult(RESULT_OK, i);
        finish();
    }

    private int rotationHint() {
        try {
            android.view.Display d = getWindowManager().getDefaultDisplay();
            return d.getRotation() * 90;
        } catch (RuntimeException e) {
            // A display we cannot ask is a display we will not rotate for. A sideways
            // preview beats a crash.
            return 0;
        }
    }
}