package app.kestrel.map;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.graphics.ImageFormat;
import android.hardware.Camera;
import android.util.Log;
import android.view.SurfaceHolder;
import android.view.SurfaceView;

import java.io.IOException;
import java.util.List;

/**
 * A camera preview that hands frames to the native decoder.
 *
 * <p>{@link Camera} rather than Camera2 or CameraX. The deprecated framework API still
 * works on every device this app supports, needs no dependencies at all, and this is
 * the only camera code in the project. One old API that does one thing is better than a
 * library that adds megabytes and a lifecycle to manage.
 *
 * <p>The frames go across as a {@code byte[]} in NV21. Java never looks at the pixels.
 */
final class CameraView extends SurfaceView implements SurfaceHolder.Callback, Camera.PreviewCallback {
    private static final String TAG = "Kestrel";

    /**
     * Preview size. Small on purpose: a QR code is legible at 640 wide.
     *
     * <p>Must match {@code SCAN_WIDTH} and {@code SCAN_HEIGHT} in the Rust scanner. The
     * native decoder is handed the frame and these two numbers and no image header, so a
     * mismatch here would read the frame at the wrong stride and find nothing.
     */
    static final int WIDTH = 640;
    static final int HEIGHT = 480;

    private final Context context;
    private final int rotation;
    private Camera camera;
    private byte[] frame;
    private volatile boolean running;

    CameraView(Context context, int rotation) {
        super(context);
        this.context = context;
        this.rotation = rotation;
        getHolder().addCallback(this);
    }

    void start() {
        running = true;
        if (getHolder().getSurface() != null && getHolder().getSurface().isValid()) {
            open();
        }
    }

    void stop() {
        running = false;
        close();
    }

    @Override
    public void surfaceCreated(SurfaceHolder h) {
        if (running) {
            open();
        }
    }

    @Override
    public void surfaceChanged(SurfaceHolder h, int format, int width, int height) {
        // Nothing. The preview size is fixed, and resizing it mid-scan would move the
        // framing the user is aiming at.
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder h) {
        // Released with the surface: holding the camera open after the preview is gone
        // means every other app's camera fails too.
        close();
    }

    private void open() {
        if (camera != null) {
            return;
        }
        if (context.checkSelfPermission(Manifest.permission.CAMERA)
                != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        try {
            Camera c = Camera.open();
            if (c == null) {
                // No camera at all. Rust has already been told and will say so.
                Bridge.reportScan("");
                return;
            }
            camera = c;
            c.setDisplayOrientation(rotation);

            Camera.Parameters p = c.getParameters();
            Camera.Size size = pick(p.getSupportedPreviewSizes());
            if (size != null) {
                p.setPreviewSize(size.width, size.height);
            }
            p.setPreviewFormat(ImageFormat.NV21);
            c.setParameters(p);

            int w = size == null ? WIDTH : size.width;
            int h = size == null ? HEIGHT : size.height;
            frame = new byte[w * h * 3 / 2];
            c.addCallbackBuffer(new byte[w * h]);

            c.setPreviewDisplay(getHolder());
            c.setPreviewCallbackWithBuffer(this);
            c.startPreview();
        } catch (IOException | RuntimeException e) {
            // The camera being busy or missing is ordinary rather than exceptional:
            // another app may hold it. Reported as an empty scan, so the user is told
            // nothing happened instead of the app dying with a camera exception.
            Log.w(TAG, "camera unavailable: " + e.getMessage());
            Bridge.reportScan("");
            close();
        }
    }

    /** The largest supported size that fits inside the one wanted. */
    private static Camera.Size pick(List<Camera.Size> sizes) {
        Camera.Size best = null;
        if (sizes == null) {
            return null;
        }
        for (Camera.Size s : sizes) {
            if (s.width > WIDTH || s.height > HEIGHT) {
                continue;
            }
            if (best == null || s.width * s.height > best.width * best.height) {
                best = s;
            }
        }
        // Nothing small enough is odd but happens; the device's own default is a better
        // guess than refusing to scan.
        if (best == null && !sizes.isEmpty()) {
            best = sizes.get(0);
        }
        return best;
    }

    private void close() {
        Camera c = camera;
        camera = null;
        if (c == null) {
            return;
        }
        try {
            c.setPreviewCallbackWithBuffer(null);
            c.stopPreview();
        } catch (RuntimeException e) {
            // Already stopped.
        }
        try {
            c.release();
        } catch (RuntimeException e) {
            // The handle goes away regardless.
        }
    }

    @Override
    public void onPreviewFrame(byte[] data, Camera cam) {
        // Only when the decoder has asked for one. A QR code sits still in the frame for
        // long enough to be read by a single frame out of thirty, and decoding all of
        // them would keep the CPU busy for nothing.
        boolean wanted = running && data != null && frame != null && Bridge.frameWanted();
        if (wanted) {
            // Copied into our own buffer because the callback's buffer is reused the
            // moment this returns and the decoder runs on another thread.
            System.arraycopy(data, 0, frame, 0, Math.min(data.length, frame.length));
        }
        // The buffer always goes back, wanted or not, or the camera stops delivering.
        if (cam != null) {
            cam.addCallbackBuffer(data);
        }
        if (wanted) {
            Bridge.pushFrame(frame.clone());
        }
    }
}