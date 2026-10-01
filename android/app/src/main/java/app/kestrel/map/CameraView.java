package app.kestrel.map;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.graphics.ImageFormat;
import android.graphics.SurfaceTexture;
import android.hardware.Camera;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;

import java.io.IOException;
import java.util.List;

/**
 * The camera, for reading one QR code.
 *
 * <p>{@link Camera} rather than Camera2 or CameraX: the deprecated framework API still
 * works on every device this app supports, needs no dependencies at all, and this is
 * the only camera code in the project. The trade is deliberate — the API is old, and
 * one old API that does one thing beats a library that adds two megabytes and a
 * lifecycle to manage.
 *
 * <p>The preview frames are handed to Rust, which decodes them. Java does not touch the
 * pixels: it hands over a {@code byte[]} and gets nothing back.
 */
final class CameraView extends SurfaceView implements SurfaceHolder.Callback, Camera.PreviewCallback {
    /** Preview size. Small on purpose: a QR code is readable at 640 wide. */
    private static final int PREVIEW_WIDTH = 640;
    private static final int PREVIEW_HEIGHT = 480;

    private final Context context;
    private final int[] rotation;
    private Camera camera;
    private SurfaceHolder holder;
    private volatile boolean running;
    private byte[] frame;

    CameraView(Context context, int[] rotation) {
        super(context);
        this.context = context;
        this.rotation = rotation;
        holder = getHolder();
        holder.addCallback(this);
        holder.setType(SurfaceHolder.SURFACE_TYPE_PUSH_BUFFERS);
    }

    void start() {
        running = true;
        if (holder != null && holder.getSurface() != null && holder.getSurface().isValid()) {
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
        // Nothing: the preview size is fixed, and resizing it would change the framing
        // the user is aiming at mid-scan.
    }

    @Override
    public void surfaceDestroyed(SurfaceHolder h) {
        // The camera is released when the surface goes, because holding it open after
        // the preview is gone means every other app's camera fails too.
        close();
    }

    private void open() {
        if (camera != null) {
            return;
        }
        if (context.checkSelfPermission(Manifest.permission.CAMERA)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            // No permission, so no camera. Rust has already been told, and will offer a
            // settings link rather than a button that cannot work.
            return;
        }
        try {
            camera = Camera.open();
            if (camera == null) {
                return;
            }
            camera.setDisplayOrientation(rotation[0]);
            Camera.Parameters p = camera.getParameters();
            List<Camera.Size> sizes = p.getSupportedPreviewSizes();
            Camera.Size best = pick(sizes);
            if (best != null) {
                p.setPreviewSize(best.width, best.height);
            }
            p.setPreviewFormat(ImageFormat.NV21);
            camera.setParameters(p);
            frame = new byte[best == null ? PREVIEW_WIDTH * PREVIEW_HEIGHT * 3 / 2
                    : best.width * best.height * 3 / 2];
            camera.setPreviewDisplay(holder);
            camera.setPreviewCallbackWithBuffer(this);
            camera.startPreview();
        } catch (IOException | RuntimeException e) {
            // The camera being busy or missing is ordinary, not exceptional: another app
            // may hold it. Reported to Rust as a failed scan rather than a crash.
            MainActivity.scanFailed("the camera is unavailable: " + e.getMessage());
            close();
        }
    }

    /** The largest supported size no bigger than the one we want. */
    private static Camera.Size pick(List<Camera.Size> sizes) {
        Camera.Size best = null;
        if (sizes == null) {
            return null;
        }
        for (Camera.Size s : sizes) {
            if (s.width > PREVIEW_WIDTH || s.height > PREVIEW_HEIGHT) {
                continue;
            }
            if (best == null || s.width * s.height > best.width * best.height) {
                best = s;
            }
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
            // Already stopped. Nothing to do.
        }
        try {
            c.release();
        } catch (RuntimeException e) {
            // Nothing to do; the handle is going away either way.
        }
    }

    @Override
    public void onPreviewFrame(byte[] data, Camera cam) {
        boolean wanted = running && data != null && frame != null && MainActivity.frameWanted();
        if (wanted) {
            // Copied into our own buffer because the callback's buffer is reused the
            // moment this returns and the decoder runs on another thread. Only when a
            // frame was actually asked for: at thirty frames a second an unconditional
            // copy would allocate half a megabyte thirty times a second for nothing.
            System.arraycopy(data, 0, frame, 0, Math.min(data.length, frame.length));
        }
        // The buffer is always returned, even when the frame was not wanted, or the
        // camera stops delivering frames entirely.
        if (cam != null) {
            cam.addCallbackBuffer(data);
        }
        if (wanted) {
            MainActivity.takeFrame(frame);
        }
    }
}