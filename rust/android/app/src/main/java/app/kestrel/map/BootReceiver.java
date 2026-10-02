package app.kestrel.map;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * Starts sharing again after a reboot or an update.
 *
 * <p>Only if the user had asked for it. A share that does not come back after a reboot
 * is a share the map still shows as running and is not, which is worse than one that
 * stops: the user believes people can see them when they cannot.
 */
public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context c, Intent intent) {
        ShareService.resumeIfWanted(c);
    }
}
