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

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.AuditEntry;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Verifies the x3dhpq audit chain (XEP-XQR §11.5) and surfaces per-entry
 * Android notifications for new entries (§11.6).
 *
 * <p>This class is stateless with respect to the chain itself; the tail hash is
 * persisted via {@link X3dhpqDao#getAuditTailHash} / {@link X3dhpqDao#setAuditTailHash}.
 */
public final class AccountAuditChainVerifier {

    /**
     * Notification channel ID for audit-chain events.
     * Reuse {@code XmppConnectionService.NOTIFICATION_CHANNEL_AUDIT} if/when that constant is
     * added; until then use this fallback.
     */
    static final String X3DHPQ_AUDIT_CHANNEL = "x3dhpq_audit";

    private static final String TAG = Config.LOGTAG;
    private static final String LOGPREFIX = "AccountAuditChainVerifier";

    private final Context ctx;
    private final X3dhpqDao dao;

    public AccountAuditChainVerifier(final Context ctx, final X3dhpqDao dao) {
        if (ctx == null) throw new IllegalArgumentException("ctx must not be null");
        if (dao == null) throw new IllegalArgumentException("dao must not be null");
        this.ctx = ctx.getApplicationContext();
        this.dao = dao;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Verifies the full chain and returns the verified entries (oldest to newest).
     *
     * <p>Verification rules (§11.5):
     * <ol>
     *   <li>If {@code chain} is empty, returns an empty list without error.</li>
     *   <li>entries[0].seq == 0 and entries[0].prevHash is all-zeros (genesis), OR if starting
     *       mid-chain, the persisted tail hash equals entries[0].prevHash.</li>
     *   <li>For i &gt;= 1: seq is contiguous, prevHash == SHA-256(entries[i-1].marshal()),
     *       timestamp is non-decreasing.</li>
     *   <li>Both Ed25519 and ML-DSA-65 signatures must verify against {@code aikPub} over
     *       {@code entry.signedPart()}.</li>
     * </ol>
     *
     * <p>On success the tail hash for {@code accountId} is updated in the DAO.
     *
     * @throws InvalidAuditChainException on any verification failure.
     */
    public List<AuditEntry> verifyAndStore(
            final long accountId,
            final AccountIdentityPub aikPub,
            final List<AuditEntry> chain)
            throws InvalidAuditChainException {

        if (chain == null || chain.isEmpty()) {
            Log.d(TAG, LOGPREFIX + ": verifyAndStore accountId=" + accountId + " chain is empty");
            return Collections.emptyList();
        }
        if (aikPub == null) {
            throw new InvalidAuditChainException("aikPub must not be null");
        }

        // Retrieve the previously-stored tail hash (null if no history).
        final byte[] storedTailHash = dao.getAuditTailHash(accountId);

        // Determine expected prevHash for entries[0].
        final AuditEntry first = chain.get(0);
        if (first.getSeq() == 0) {
            // Genesis entry: prevHash must be 32 zero bytes.
            final byte[] genesisExpected = new byte[32];
            if (!Arrays.equals(first.getPrevHash(), genesisExpected)) {
                throw new InvalidAuditChainException(
                        "genesis entry (seq=0) prevHash must be all-zero bytes");
            }
        } else {
            // Mid-chain: prevHash of the first entry must match the stored tail hash.
            if (storedTailHash == null) {
                throw new InvalidAuditChainException(
                        "mid-chain start (seq=" + first.getSeq()
                        + ") but no persisted tail hash; cannot anchor chain");
            }
            if (!Arrays.equals(first.getPrevHash(), storedTailHash)) {
                throw new InvalidAuditChainException(
                        "mid-chain start (seq=" + first.getSeq()
                        + ") prevHash does not match persisted tail hash");
            }
        }

        // Walk all entries validating signatures, seq, prevHash linkage, timestamp monotonicity.
        byte[] prevHash = first.getPrevHash(); // anchors the hash chain for position 0
        AuditEntry prev = null;

        for (int i = 0; i < chain.size(); i++) {
            final AuditEntry entry = chain.get(i);

            // --- sequence number ---
            final long expectedSeq = (first.getSeq()) + i;
            if (entry.getSeq() != expectedSeq) {
                throw new InvalidAuditChainException(
                        "entry at position " + i + " has seq=" + entry.getSeq()
                        + " but expected " + expectedSeq);
            }

            // --- prevHash linkage ---
            if (!Arrays.equals(entry.getPrevHash(), prevHash)) {
                throw new InvalidAuditChainException(
                        "entry seq=" + entry.getSeq() + " prevHash mismatch");
            }

            // --- timestamp monotonicity (for i > 0) ---
            if (prev != null && entry.getTimestamp() < prev.getTimestamp()) {
                throw new InvalidAuditChainException(
                        "entry seq=" + entry.getSeq()
                        + " timestamp " + entry.getTimestamp()
                        + " is less than previous entry timestamp " + prev.getTimestamp());
            }

            // --- signature verification ---
            final byte[] signedPart = entry.signedPart();

            final byte[] sigEd = entry.getSigEd25519();
            if (sigEd == null || sigEd.length == 0) {
                throw new InvalidAuditChainException(
                        "entry seq=" + entry.getSeq() + " missing Ed25519 signature");
            }
            try {
                if (!X3dhpqCrypto.ed25519Verify(aikPub.getPubEd25519(), signedPart, sigEd)) {
                    throw new InvalidAuditChainException(
                            "entry seq=" + entry.getSeq() + " Ed25519 signature invalid");
                }
            } catch (InvalidAuditChainException e) {
                throw e;
            } catch (Exception e) {
                throw new InvalidAuditChainException(
                        "entry seq=" + entry.getSeq() + " Ed25519 verification error: " + e.getMessage(), e);
            }

            final byte[] sigMLDSA = entry.getSigMLDSA();
            if (sigMLDSA == null || sigMLDSA.length == 0) {
                throw new InvalidAuditChainException(
                        "entry seq=" + entry.getSeq() + " missing ML-DSA-65 signature");
            }
            try {
                if (!X3dhpqCrypto.mldsa65Verify(aikPub.getPubMLDSA(), signedPart, sigMLDSA)) {
                    throw new InvalidAuditChainException(
                            "entry seq=" + entry.getSeq() + " ML-DSA-65 signature invalid");
                }
            } catch (InvalidAuditChainException e) {
                throw e;
            } catch (Exception e) {
                throw new InvalidAuditChainException(
                        "entry seq=" + entry.getSeq() + " ML-DSA-65 verification error: " + e.getMessage(), e);
            }

            // Advance the prevHash cursor for the next iteration.
            prevHash = sha256(entry.marshal());
            prev = entry;
        }

        // All entries verified. Persist the new tail hash.
        dao.setAuditTailHash(accountId, prevHash);

        Log.d(TAG, LOGPREFIX + ": verifyAndStore accountId=" + accountId
                + " verified " + chain.size() + " entries"
                + " tailSeq=" + chain.get(chain.size() - 1).getSeq());

        return Collections.unmodifiableList(new ArrayList<>(chain));
    }

    /**
     * Posts an Android notification for each entry whose seq exceeds {@code prevTailSeq}.
     * Idempotent — may be called on every chain refresh.
     *
     * @param accountAddress bare JID of the account (used as the notification title context
     *                       and as a seed for the notification ID).
     * @param chain          the verified chain (oldest to newest).
     * @param prevTailSeq    last seq already known to the user (exclusive lower bound).
     *                       Pass {@code -1} to notify about every entry in the chain.
     */
    public void notifyNewEntries(
            final String accountAddress,
            final List<AuditEntry> chain,
            final long prevTailSeq) {

        if (chain == null || chain.isEmpty()) {
            return;
        }

        ensureNotificationChannel();

        final NotificationManagerCompat nm = NotificationManagerCompat.from(ctx);

        for (final AuditEntry entry : chain) {
            if (entry.getSeq() <= prevTailSeq) {
                continue;
            }

            final String text = notificationTextForAction(entry.getAction());
            if (text == null) {
                // Unknown action type; skip silently.
                Log.d(TAG, LOGPREFIX + ": notifyNewEntries skipping unknown action="
                        + entry.getAction() + " seq=" + entry.getSeq());
                continue;
            }

            // Notification ID: accountAddress.hashCode() XOR entry seq, guaranteed distinct
            // per (account, entry) pair.
            final int notifId = accountAddress.hashCode() ^ (int) entry.getSeq();

            final NotificationCompat.Builder builder =
                    new NotificationCompat.Builder(ctx, X3DHPQ_AUDIT_CHANNEL)
                            .setSmallIcon(android.R.drawable.ic_dialog_alert)
                            .setContentTitle(accountAddress)
                            .setContentText(text)
                            .setStyle(new NotificationCompat.BigTextStyle().bigText(text))
                            .setPriority(NotificationCompat.PRIORITY_HIGH)
                            .setAutoCancel(true);

            try {
                nm.notify(notifId, builder.build());
                Log.d(TAG, LOGPREFIX + ": notifyNewEntries posted notifId=" + notifId
                        + " action=" + entry.getAction() + " seq=" + entry.getSeq());
            } catch (SecurityException e) {
                // POST_NOTIFICATIONS permission not granted; log and continue.
                Log.d(TAG, LOGPREFIX + ": notifyNewEntries SecurityException (no permission): "
                        + e.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Maps an AuditEntry action code to the human-readable notification body per §11.6.
     * Returns {@code null} for unknown action codes.
     */
    private static String notificationTextForAction(final int action) {
        switch (action) {
            case AuditEntry.ACTION_ADD_DEVICE:
                return "A new device was added to your account.";
            case AuditEntry.ACTION_REMOVE_DEVICE:
                return "A device was removed from your account.";
            case AuditEntry.ACTION_ROTATE_AIK:
                return "Your account's identity key has rotated."
                        + " If this was not you, your primary device may be compromised.";
            case AuditEntry.ACTION_RECOVER_FROM_BACKUP:
                return "Your account was recovered from a backup.";
            default:
                return null;
        }
    }

    /**
     * Creates the audit notification channel on API 26+. No-op on older platforms and
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
        if (nm.getNotificationChannel(X3DHPQ_AUDIT_CHANNEL) != null) {
            return;
        }
        final NotificationChannel channel = new NotificationChannel(
                X3DHPQ_AUDIT_CHANNEL,
                "Account Security Audit",
                NotificationManager.IMPORTANCE_HIGH);
        channel.setDescription("Alerts for x3dhpq account identity-key events");
        nm.createNotificationChannel(channel);
    }

    /**
     * Computes SHA-256 using the standard JCA provider (always present on Android).
     * The {@link im.conversations.x3dhpq.types.Sha256} interface is test-only; production
     * hash chaining uses this direct call to avoid an unnecessary dependency injection point.
     */
    private static byte[] sha256(final byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (final NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the Android CDD; this branch is unreachable in production.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    // -------------------------------------------------------------------------
    // Exception type
    // -------------------------------------------------------------------------

    /** Thrown when the audit chain fails any verification rule from §11.5. */
    public static class InvalidAuditChainException extends Exception {

        public InvalidAuditChainException(final String message) {
            super(message);
        }

        public InvalidAuditChainException(final String message, final Throwable cause) {
            super(message, cause);
        }
    }
}
