// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import android.util.Log;
import com.google.common.io.BaseEncoding;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.model.stanza.Message;
import im.conversations.android.xmpp.model.x3dhpq.pair.Pair;
import im.conversations.x3dhpq.protocol.PairingFsm;
import im.conversations.x3dhpq.types.AccountIdentityKey;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import im.conversations.x3dhpq.types.PairingMsg;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Owns the lifetime of in-flight pairing FSMs (one per CPace {@code sid}), routing inbound
 * pair-stanza payloads to the correct FSM and sending outbound replies.
 *
 * <p>FSMs are kept in-memory only; the DB row stores role/peerJid/code/expiresAt for sweep
 * purposes. Per spec §10.5, a 60-second TTL applies — if the process dies mid-pairing the user
 * must restart.
 */
public final class PairingSessionService {

    private static final String LOGTAG = "PairingSessionService";

    /** role value stored in DB: existing/initiator side */
    private static final int ROLE_EXISTING = 0;

    /** role value stored in DB: new/responder side */
    private static final int ROLE_NEW = 1;

    /** Session TTL in seconds (matches spec §10.5) */
    private static final long TTL_SECONDS = 60L;

    public interface Listener {
        void onPairingComplete(
                byte[] sid, PairingFsm.Result result, DeviceCertificate issuedCert);

        void onPairingFailed(byte[] sid, Throwable error);
    }

    private final Account account;
    private final XmppConnectionService xmppConnectionService;
    private final X3dhpqDao dao;

    /** Guards both FSM maps. */
    private final Object lock = new Object();

    /** In-flight Existing-side FSMs, keyed by sid as ByteBuffer (for value-equality). */
    private final Map<ByteBuffer, PairingFsm.Existing> existingFsms = new HashMap<>();

    /**
     * In-flight New-side FSMs, keyed by sid as ByteBuffer. Also tracks the step counter so we can
     * set {@code step} on outbound stanzas correctly.
     */
    private final Map<ByteBuffer, PairingFsm.New> newFsms = new HashMap<>();

    /**
     * Per-sid outbound step counter. Incremented each time we send a stanza for that sid.
     * Shared between Existing and New sides.
     */
    private final Map<ByteBuffer, Integer> outboundStepCounters = new HashMap<>();

    private final List<Listener> listeners = new ArrayList<>();

    private final ExecutorService executor =
            Executors.newSingleThreadScheduledExecutor(
                    r -> {
                        Thread t = new Thread(r, "PairingSessionService");
                        t.setDaemon(true);
                        return t;
                    });

    public PairingSessionService(
            final Account account,
            final XmppConnectionService svc,
            final X3dhpqDao dao) {
        if (account == null || svc == null || dao == null) {
            throw new IllegalArgumentException("account, svc, and dao must not be null");
        }
        this.account = account;
        this.xmppConnectionService = svc;
        this.dao = dao;
    }

    public void addListener(final Listener l) {
        synchronized (lock) {
            listeners.add(l);
        }
    }

    public void removeListener(final Listener l) {
        synchronized (lock) {
            listeners.remove(l);
        }
    }

    /**
     * Existing-side: caller has just shown the pairing code. Creates an {@link PairingFsm.Existing}
     * FSM bound to {@code sid}, derives PAKE1, and sends the first pair stanza to {@code peerJid}.
     */
    public void startAsExisting(
            final byte[] sid,
            final String code,
            final Jid peerJid,
            final PairingFsm.Options opts)
            throws Exception {
        final AccountIdentityKey aik = loadAik();
        final PairingFsm.Existing fsm = new PairingFsm.Existing(aik, code, sid, opts);

        final ByteBuffer key = ByteBuffer.wrap(sid.clone());
        synchronized (lock) {
            existingFsms.put(key, fsm);
            outboundStepCounters.put(key, 0);
        }

        // Persist DB row so sweepExpired() can clean up if the process stalls.
        final long expiresAt = System.currentTimeMillis() / 1000L + TTL_SECONDS;
        dao.putX3dhpqPairingSession(
                account.getUuid(), sid, ROLE_EXISTING, peerJid.toString(), code,
                new byte[0], expiresAt);

        // Drive FSM to produce PAKE1 (step(null) in INIT state).
        executor.execute(() -> {
            try {
                final PairingMsg out = fsm.step(null);
                if (out != null) {
                    sendPairStanza(peerJid, sid, out, key);
                }
                dao.updateX3dhpqPairingState(sid, new byte[0]);
            } catch (Exception e) {
                Log.w(Config.LOGTAG, LOGTAG + ": startAsExisting FSM init failed for sid="
                        + hexSid(sid) + ": " + e.getMessage());
                cleanupSession(key, sid);
                notifyFailure(sid, e);
            }
        });
    }

    /**
     * New-side: caller has scanned/typed the pairing code. Creates a {@link PairingFsm.New} FSM
     * bound to {@code sid}. The first inbound stanza will drive it forward.
     */
    public void prepareAsNew(final byte[] sid, final String code, final Jid peerJid)
            throws Exception {
        final DeviceIdentityKey dik = loadDik();
        final PairingFsm.New fsm = new PairingFsm.New(dik, code, sid);

        final ByteBuffer key = ByteBuffer.wrap(sid.clone());
        synchronized (lock) {
            newFsms.put(key, fsm);
            outboundStepCounters.put(key, 0);
        }

        final long expiresAt = System.currentTimeMillis() / 1000L + TTL_SECONDS;
        dao.putX3dhpqPairingSession(
                account.getUuid(), sid, ROLE_NEW, peerJid.toString(), code,
                new byte[0], expiresAt);
    }

    /**
     * Inbound: dispatches a freshly-arrived pair stanza to its FSM (matched by sid). Calls {@link
     * Listener#onPairingComplete} or {@link Listener#onPairingFailed} on the registered listeners.
     */
    public void onIncoming(final Message packet) throws Exception {
        final Pair pair = packet.getExtension(Pair.class);
        if (pair == null) {
            Log.d(Config.LOGTAG, LOGTAG + ": onIncoming called with no <pair> extension, dropping");
            return;
        }

        final String sidBase64 = pair.getSid();
        if (sidBase64 == null || sidBase64.isEmpty()) {
            Log.w(Config.LOGTAG, LOGTAG + ": <pair> missing sid attribute, dropping");
            return;
        }

        final byte[] sid;
        try {
            sid = BaseEncoding.base64().decode(sidBase64);
        } catch (IllegalArgumentException e) {
            Log.w(Config.LOGTAG, LOGTAG + ": <pair> has invalid base64 sid, dropping");
            return;
        }

        final byte[] msgBytes = pair.asBytes();
        final PairingMsg inMsg;
        try {
            inMsg = PairingMsg.unmarshal(msgBytes);
        } catch (IllegalArgumentException e) {
            Log.w(Config.LOGTAG, LOGTAG + ": <pair> body unmarshal failed for sid="
                    + hexSid(sid) + ": " + e.getMessage());
            return;
        }

        final ByteBuffer key = ByteBuffer.wrap(sid);

        // Determine which FSM type holds this sid and dispatch accordingly.
        final PairingFsm.Existing existingFsm;
        final PairingFsm.New newFsm;
        synchronized (lock) {
            existingFsm = existingFsms.get(key);
            newFsm = newFsms.get(key);
        }

        if (existingFsm != null) {
            dispatchToExisting(existingFsm, key, sid, inMsg, packet.getFrom());
        } else if (newFsm != null) {
            dispatchToNew(newFsm, key, sid, inMsg, packet.getFrom());
        } else {
            Log.d(Config.LOGTAG, LOGTAG + ": no FSM registered for sid=" + hexSid(sid) + ", dropping");
        }
    }

    /**
     * Periodic sweeper — deletes expired DB rows. Call this on a timer (e.g. every 30 s).
     */
    public void sweepExpired() {
        executor.execute(() -> {
            final long nowSeconds = System.currentTimeMillis() / 1000L;
            final int swept = dao.sweepExpiredX3dhpqPairingSessions(nowSeconds);
            if (swept > 0) {
                Log.d(Config.LOGTAG, LOGTAG + ": swept " + swept + " expired pairing session(s)");
            }
        });
    }

    // ---- private dispatch helpers ----

    private void dispatchToExisting(
            final PairingFsm.Existing fsm,
            final ByteBuffer key,
            final byte[] sid,
            final PairingMsg inMsg,
            final Jid from) {
        executor.execute(() -> {
            try {
                final PairingMsg out;
                synchronized (lock) {
                    out = fsm.step(inMsg);
                }
                dao.updateX3dhpqPairingState(sid, new byte[0]);

                if (out != null) {
                    final Jid replyTo = from != null ? from : null;
                    if (replyTo != null) {
                        sendPairStanza(replyTo, sid, out, key);
                    }
                }

                if (fsm.isDone()) {
                    cleanupSession(key, sid);
                    final DeviceCertificate issuedCert = fsm.getIssuedCert();
                    notifyComplete(sid, null, issuedCert);
                }
            } catch (Exception e) {
                Log.w(Config.LOGTAG, LOGTAG + ": Existing FSM step failed for sid="
                        + hexSid(sid) + ": " + e.getMessage());
                cleanupSession(key, sid);
                notifyFailure(sid, e);
            }
        });
    }

    private void dispatchToNew(
            final PairingFsm.New fsm,
            final ByteBuffer key,
            final byte[] sid,
            final PairingMsg inMsg,
            final Jid from) {
        executor.execute(() -> {
            try {
                final PairingMsg out;
                synchronized (lock) {
                    out = fsm.step(inMsg);
                }
                dao.updateX3dhpqPairingState(sid, new byte[0]);

                if (out != null && from != null) {
                    sendPairStanza(from, sid, out, key);
                }

                // After SENT_PAKE1 → SENT_CONFIRM: the FSM produced a TYPE_CONFIRM back, and
                // the protocol immediately requires us to call step(null) to advance to WAIT_DIK,
                // producing the encrypted DIK payload. We detect this by checking the output type.
                if (out != null && out.getType() == PairingMsg.TYPE_CONFIRM && !fsm.isDone()) {
                    final PairingMsg dikPayload;
                    synchronized (lock) {
                        dikPayload = fsm.step(null);
                    }
                    dao.updateX3dhpqPairingState(sid, new byte[0]);
                    if (dikPayload != null && from != null) {
                        sendPairStanza(from, sid, dikPayload, key);
                    }
                }

                if (fsm.isDone()) {
                    cleanupSession(key, sid);
                    final PairingFsm.Result result = fsm.getResult();
                    notifyComplete(sid, result, null);
                }
            } catch (Exception e) {
                Log.w(Config.LOGTAG, LOGTAG + ": New FSM step failed for sid="
                        + hexSid(sid) + ": " + e.getMessage());
                cleanupSession(key, sid);
                notifyFailure(sid, e);
            }
        });
    }

    // ---- stanza building ----

    private void sendPairStanza(
            final Jid to,
            final byte[] sid,
            final PairingMsg pairingMsg,
            final ByteBuffer key) {
        final int step;
        synchronized (lock) {
            final Integer current = outboundStepCounters.getOrDefault(key, 0);
            step = current;
            outboundStepCounters.put(key, current + 1);
        }

        final Message packet = new Message(Message.Type.CHAT);
        packet.setTo(to);
        packet.setFrom(account.getJid());

        final Pair pair = new Pair();
        pair.setSid(BaseEncoding.base64().encode(sid));
        pair.setStep(step);
        pair.setContent(pairingMsg.marshal());
        packet.addExtension(pair);

        xmppConnectionService.sendMessagePacket(account, packet);
        Log.d(Config.LOGTAG, LOGTAG + ": sent pair stanza to=" + to
                + " sid=" + hexSid(sid) + " step=" + step
                + " msgType=" + pairingMsg.getType());
    }

    // ---- helpers ----

    private void cleanupSession(final ByteBuffer key, final byte[] sid) {
        synchronized (lock) {
            existingFsms.remove(key);
            newFsms.remove(key);
            outboundStepCounters.remove(key);
        }
        try {
            dao.deleteX3dhpqPairingSession(sid);
        } catch (Exception e) {
            Log.w(Config.LOGTAG, LOGTAG + ": failed to delete pairing session row: " + e.getMessage());
        }
    }

    private void notifyComplete(
            final byte[] sid,
            final PairingFsm.Result result,
            final DeviceCertificate issuedCert) {
        final List<Listener> snapshot;
        synchronized (lock) {
            snapshot = new ArrayList<>(listeners);
        }
        for (final Listener l : snapshot) {
            try {
                l.onPairingComplete(sid, result, issuedCert);
            } catch (Exception e) {
                Log.w(Config.LOGTAG, LOGTAG + ": listener threw in onPairingComplete: " + e.getMessage());
            }
        }
    }

    private void notifyFailure(final byte[] sid, final Throwable error) {
        final List<Listener> snapshot;
        synchronized (lock) {
            snapshot = new ArrayList<>(listeners);
        }
        for (final Listener l : snapshot) {
            try {
                l.onPairingFailed(sid, error);
            } catch (Exception e) {
                Log.w(Config.LOGTAG, LOGTAG + ": listener threw in onPairingFailed: " + e.getMessage());
            }
        }
    }

    private AccountIdentityKey loadAik() {
        final DatabaseBackend.X3dhpqAccountIdentityRow row =
                dao.loadX3dhpqAccountIdentity(account.getUuid());
        if (row == null || row.aikPriv() == null) {
            throw new IllegalStateException("no AccountIdentityKey row for " + account.getUuid());
        }
        return AccountIdentityKey.unmarshal(row.aikPriv());
    }

    private DeviceIdentityKey loadDik() {
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows =
                dao.listX3dhpqLocalDevices(account.getUuid());
        if (rows.isEmpty()) {
            throw new IllegalStateException("no local device row for " + account.getUuid());
        }
        return DeviceIdentityKey.unmarshal(rows.get(0).dikPriv());
    }

    private static String hexSid(final byte[] sid) {
        if (sid == null) return "null";
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(sid.length, 8); i++) {
            sb.append(String.format("%02x", sid[i] & 0xff));
        }
        if (sid.length > 8) sb.append("...");
        return sb.toString();
    }
}
