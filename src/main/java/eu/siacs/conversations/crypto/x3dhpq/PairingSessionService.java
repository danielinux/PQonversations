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

    /**
     * Per-sid peer JID this FSM is bound to. Existing-side: the new device we sent PAKE1 to.
     * New-side: the existing device that sent us the first valid PAKE1 (locked on first contact).
     * On a multi-resource account, message carbons fan every directed {@code <pair>} stanza out to
     * all of our resources, so we may see PAKE traffic from OTHER resources — we handshake with
     * exactly one peer and drop the rest.
     */
    private final Map<ByteBuffer, Jid> sessionPeers = new HashMap<>();

    /**
     * New-side pairing code per sid, kept so the responder can re-arm a fresh FSM if a stray
     * existing device races in and fails key confirmation. Without this, one bogus initiator (e.g.
     * a ghost session replaying a stale code) would tear the session down before the genuine device
     * gets to complete.
     */
    private final Map<ByteBuffer, String> newCodes = new HashMap<>();

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
            // Bind this INITIATOR to the single new device we're pairing with, so
            // carbon'd/foreign PAKE traffic from other resources is dropped.
            if (peerJid != null && !peerJid.asBareJid().equals(peerJid)) {
                sessionPeers.put(key, peerJid);
            }
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
            newCodes.put(key, code);
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
        // Bind to the single new device we sent PAKE1 to; drop carbon'd/foreign traffic.
        final Jid boundPeer;
        synchronized (lock) {
            boundPeer = sessionPeers.get(key);
        }
        if (boundPeer != null && (from == null || !boundPeer.equals(from))) {
            Log.w(Config.LOGTAG, "X3DHPQ-PAIR: EXISTING dropping stanza type=" + inMsg.getType()
                    + " from non-peer " + from + " (peer=" + boundPeer + ")");
            return;
        }
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
            } catch (PairingFsm.PairingException e) {
                if (isStrayStanza(e)) {
                    // A stray/duplicate/out-of-order stanza (carbon copy of a message we
                    // already consumed, or one for a different FSM step). The FSM checks the
                    // message type BEFORE mutating state, so nothing was corrupted — ignore
                    // it and keep the session alive.
                    Log.w(Config.LOGTAG, "X3DHPQ-PAIR: EXISTING ignoring stray stanza type="
                            + inMsg.getType() + " from " + from + ": " + e.getMessage());
                    return;
                }
                Log.w(Config.LOGTAG, LOGTAG + ": Existing FSM step failed for sid="
                        + hexSid(sid) + ": " + e.getMessage());
                cleanupSession(key, sid);
                notifyFailure(sid, e);
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
        // Lock onto the first existing device that reaches us; ignore stanzas from any other
        // resource. Several existing resources may race to initiate and carbons duplicate each
        // one's traffic across all our resources — we handshake with exactly one peer. The lock
        // is only committed AFTER a message from a peer validly advances the FSM (below), so a
        // bogus/stray first stanza can't hijack the session.
        synchronized (lock) {
            final Jid locked = sessionPeers.get(key);
            if (locked != null && (from == null || !locked.equals(from))) {
                Log.w(Config.LOGTAG, "X3DHPQ-PAIR: NEW dropping stanza type=" + inMsg.getType()
                        + " from non-peer " + from + " (locked=" + locked + ")");
                return;
            }
        }
        executor.execute(() -> {
            try {
                final PairingMsg out;
                synchronized (lock) {
                    out = fsm.step(inMsg);
                    // Commit the peer lock now that this sender validly advanced the FSM.
                    if (from != null && sessionPeers.get(key) == null) {
                        sessionPeers.put(key, from);
                    }
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
            } catch (PairingFsm.PairingException e) {
                if (isStrayStanza(e)) {
                    Log.w(Config.LOGTAG, "X3DHPQ-PAIR: NEW ignoring stray stanza type="
                            + inMsg.getType() + " from " + from + ": " + e.getMessage());
                    return;
                }
                // Key-confirm failed for the peer we locked onto. On a polluted account this is
                // typically a ghost/stray existing device replaying a stale code — NOT the genuine
                // device the user is pairing. Re-arm a fresh New FSM (fresh CPace state) for the
                // same sid+code and drop the lock, so the real device can still complete. The
                // session only truly ends on TTL expiry (sweepExpired).
                if (rearmNewFsm(key, sid, from, e)) {
                    return;
                }
                Log.w(Config.LOGTAG, LOGTAG + ": New FSM step failed for sid="
                        + hexSid(sid) + ": " + e.getMessage());
                cleanupSession(key, sid);
                notifyFailure(sid, e);
            } catch (Exception e) {
                Log.w(Config.LOGTAG, LOGTAG + ": New FSM step failed for sid="
                        + hexSid(sid) + ": " + e.getMessage());
                cleanupSession(key, sid);
                notifyFailure(sid, e);
            }
        });
    }

    /**
     * Re-arm the New-side FSM after a locked peer fails key confirmation, so a stray/ghost
     * initiator can't tear down a session the genuine device may still complete. Returns true if the
     * session was successfully re-armed (caller should stop and keep waiting), false if it could not
     * be (caller should fail the session normally).
     */
    private boolean rearmNewFsm(final ByteBuffer key, final byte[] sid, final Jid failedPeer,
            final PairingFsm.PairingException cause) {
        final String code;
        synchronized (lock) {
            code = newCodes.get(key);
            // Only re-arm if this is still the active New session for this sid.
            if (code == null || !newFsms.containsKey(key)) {
                return false;
            }
        }
        try {
            final PairingFsm.New fresh = new PairingFsm.New(loadDik(), code, sid);
            synchronized (lock) {
                newFsms.put(key, fresh);
                outboundStepCounters.put(key, 0);
                sessionPeers.remove(key);
            }
            Log.w(Config.LOGTAG, "X3DHPQ-PAIR: NEW re-armed after auth-fail from stray " + failedPeer
                    + " (sid=" + hexSid(sid) + "); still waiting for the genuine device");
            return true;
        } catch (final Exception rebuild) {
            Log.w(Config.LOGTAG, LOGTAG + ": failed to re-arm New FSM for sid=" + hexSid(sid)
                    + ": " + rebuild.getMessage());
            return false;
        }
    }

    /**
     * A {@link PairingFsm.PairingException} means either an unexpected/duplicate stanza
     * ("protocol violation" — safe to ignore, the FSM validates type before mutating state) or a
     * genuine crypto failure ("authentication failed" — fatal, wrong code). Only the former is a
     * stray that we drop while keeping the session alive.
     */
    private static boolean isStrayStanza(final PairingFsm.PairingException e) {
        final String msg = e.getMessage();
        return msg != null && msg.contains("protocol violation");
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

        // Pairing stanzas are strictly point-to-point between two devices. Tell the server NOT to
        // carbon-copy them to the account's other resources (XEP-0280 <private/> + XEP-0334
        // <no-copy/>) — otherwise every resource sees the handshake traffic and races/duplicates it.
        packet.addExtension(new im.conversations.android.xmpp.model.carbons.Private());
        packet.addExtension(new im.conversations.android.xmpp.model.hints.NoCopy());

        xmppConnectionService.sendMessagePacket(account, packet);
        Log.d(Config.LOGTAG, LOGTAG + ": sent pair stanza to=" + to
                + " sid=" + hexSid(sid) + " step=" + step + " msgType=" + pairingMsg.getType());
    }

    // ---- helpers ----

    private void cleanupSession(final ByteBuffer key, final byte[] sid) {
        synchronized (lock) {
            existingFsms.remove(key);
            newFsms.remove(key);
            outboundStepCounters.remove(key);
            sessionPeers.remove(key);
            newCodes.remove(key);
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
