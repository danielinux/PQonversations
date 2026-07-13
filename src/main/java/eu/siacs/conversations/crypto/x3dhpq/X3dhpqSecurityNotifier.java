// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import eu.siacs.conversations.Config;

/**
 * Posts free-form x3dhpq account-security notifications (e.g. §10.6.5 identity
 * reconstruction). This is the surviving remnant of the (now-removed) account audit-chain
 * verifier: device trust is driven entirely by the Trust Manifest fold, but the
 * out-of-band security notifications it once carried are still needed by the
 * identity-reconstruction path.
 */
public final class X3dhpqSecurityNotifier {

    /** Notification channel ID for x3dhpq account-security events. */
    static final String X3DHPQ_SECURITY_CHANNEL = "x3dhpq_audit";

    private static final String TAG = Config.LOGTAG;
    private static final String LOGPREFIX = "X3dhpqSecurityNotifier";

    private final Context ctx;

    public X3dhpqSecurityNotifier(final Context ctx) {
        if (ctx == null) throw new IllegalArgumentException("ctx must not be null");
        this.ctx = ctx.getApplicationContext();
    }

    /**
     * Posts a free-form security-event notification (§10.6.5 identity reconstruction).
     * Used for events detected OUTSIDE any chain (e.g. an AIK-signature mismatch against a
     * pinned peer AIK).
     *
     * @param subjectAddress bare JID used as both the notification title and the seed
     *                       for a stable-per-subject notification id (so a repeat event
     *                       for the same subject updates rather than stacks).
     * @param text           human-readable body describing the event.
     */
    public void notifySecurityEvent(final String subjectAddress, final String text) {
        if (subjectAddress == null || text == null) {
            return;
        }
        ensureNotificationChannel();
        final NotificationManagerCompat nm = NotificationManagerCompat.from(ctx);
        final int notifId = subjectAddress.hashCode() ^ 0x53455343; // 'SESC' salt
        final NotificationCompat.Builder builder =
                new NotificationCompat.Builder(ctx, X3DHPQ_SECURITY_CHANNEL)
                        .setSmallIcon(android.R.drawable.ic_dialog_alert)
                        .setContentTitle(subjectAddress)
                        .setContentText(text)
                        .setStyle(new NotificationCompat.BigTextStyle().bigText(text))
                        .setPriority(NotificationCompat.PRIORITY_HIGH)
                        .setAutoCancel(true);
        try {
            nm.notify(notifId, builder.build());
            Log.d(TAG, LOGPREFIX + ": notifySecurityEvent posted for " + subjectAddress);
        } catch (SecurityException e) {
            Log.d(TAG, LOGPREFIX + ": notifySecurityEvent SecurityException (no permission): "
                    + e.getMessage());
        }
    }

    /**
     * Creates the security notification channel on API 26+. No-op on older platforms and
     * idempotent (NotificationManager ignores re-registration with identical parameters).
     */
    private void ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        final NotificationManager nm =
                (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) {
            return;
        }
        if (nm.getNotificationChannel(X3DHPQ_SECURITY_CHANNEL) != null) {
            return;
        }
        final NotificationChannel channel = new NotificationChannel(
                X3DHPQ_SECURITY_CHANNEL,
                "Account Security Audit",
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Alerts for x3dhpq account identity-key events");
        nm.createNotificationChannel(channel);
    }
}
