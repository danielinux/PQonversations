package eu.siacs.conversations.crypto.x3dhpq;

import android.util.Log;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.crypto.x3dhpq.XmppX3dhpqMessage;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.entities.Conversation;
import eu.siacs.conversations.entities.Message;
import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.xml.Namespace;
import eu.siacs.conversations.xmpp.Jid;
import eu.siacs.conversations.crypto.x3dhpq.protocol.BundleParser;
import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.Extension;
import im.conversations.android.xmpp.model.pubsub.Items;
import im.conversations.android.xmpp.model.pubsub.PubSub;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.x3dhpq.audit.AuditEntry;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Dc;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Cert;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Device;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.MldsaSig;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Sig;
import im.conversations.android.xmpp.model.x3dhpq.group.MembershipEntry;
import im.conversations.android.xmpp.model.x3dhpq.recovery.Recovery;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.protocol.BundleData;
import im.conversations.x3dhpq.protocol.PqxdhInitiator;
import im.conversations.x3dhpq.protocol.PqxdhResponder;
import im.conversations.x3dhpq.protocol.PqxdhResult;
import im.conversations.x3dhpq.protocol.PrekeyEnvelope;
import im.conversations.x3dhpq.protocol.Session;
import im.conversations.x3dhpq.types.AccountIdentityKey;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Per-account hub for x3dhpq state and inbound PEP event dispatch.
 * Inbound devicelist/bundle events are verified and persisted (D3).
 */
public class X3dhpqService {

    public static final String LOGPREFIX = "X3dhpqService";

    /**
     * §10.6.5 re-trust gate: {@link eu.siacs.conversations.entities.Conversation} attribute
     * (reuses the existing generic attributes JSON — no schema change, mirrors the WS5
     * {@code ATTRIBUTE_PQ_UPGRADED} pattern) set true when an inbound devicelist from this
     * peer failed AIK-signature verification against our previously pinned AIK (a likely
     * identity reconstruction / fork, §8.5). Cleared only by explicit user action via
     * {@link #reTrustIdentity}.
     */
    public static final String ATTRIBUTE_X3DHPQ_IDENTITY_BLOCKED = "x3dhpq_identity_blocked";

    // Listener interfaces for inbound PEP event types.

    public interface DeviceListListener {
        void onDeviceListReceived(Jid from, DeviceList list);
    }

    public interface BundleListener {
        // deviceId is the numeric device-id string parsed as int from the item id.
        void onBundleReceived(Jid from, int deviceId, Bundle bundle);
    }

    public interface AuditListener {
        void onAuditEntryReceived(Jid from, String itemId, AuditEntry entry);
    }

    public interface MembershipListener {
        void onMembershipEntryReceived(Jid roomJid, String itemId, MembershipEntry entry);
    }

    public interface RecoveryListener {
        void onRecoveryReceived(Jid from, Recovery recovery);
    }

    private final Account account;
    private final XmppConnectionService mXmppConnectionService;
    // db may be null in the test-only no-arg constructor; null-checked before use
    private final X3dhpqDao db;

    // Registered listeners; last set wins (used for AUDIT/GROUP/RECOVERY dispatch).
    private DeviceListListener deviceListListener;
    private BundleListener bundleListener;
    private AuditListener auditListener;
    private MembershipListener membershipListener;
    private RecoveryListener recoveryListener;

    /** Lazy singleton; null when running in a test-only context (account == null). */
    private PairingSessionService pairingSessionService;

    public X3dhpqService(final Account account, final XmppConnectionService svc) {
        if (account == null || svc == null) {
            throw new IllegalArgumentException("account and service cannot be null");
        }
        this.account = account;
        this.mXmppConnectionService = svc;
        this.db = svc.databaseBackend; // DatabaseBackend implements X3dhpqDao
    }

    /**
     * Test-only constructor; skips null checks so unit tests can pass null for account/svc.
     */
    X3dhpqService() {
        this.account = null;
        this.mXmppConnectionService = null;
        this.db = null;
    }

    /**
     * Test-only constructor with an injectable DAO and no real service.
     * Used by D3 inbound tests.
     */
    X3dhpqService(final X3dhpqDao db) {
        this.account = null;
        this.mXmppConnectionService = null;
        this.db = db;
    }

    public void setDeviceListListener(final DeviceListListener l) {
        this.deviceListListener = l;
    }

    public void setBundleListener(final BundleListener l) {
        this.bundleListener = l;
    }

    public void setAuditListener(final AuditListener l) {
        this.auditListener = l;
    }

    public void setMembershipListener(final MembershipListener l) {
        this.membershipListener = l;
    }

    public void setRecoveryListener(final RecoveryListener l) {
        this.recoveryListener = l;
    }

    /**
     * Returns the lazily-created {@link PairingSessionService} for this account.
     * Returns {@code null} when {@code account} or {@code db} is not available
     * (test-only construction paths).
     */
    public synchronized PairingSessionService getPairingSessionService() {
        if (account == null || mXmppConnectionService == null || db == null) {
            return null;
        }
        if (pairingSessionService == null) {
            pairingSessionService = new PairingSessionService(account, mXmppConnectionService, db);
        }
        return pairingSessionService;
    }

    /**
     * Routes a parsed inbound PEP event item to the appropriate default handler or listener slot.
     * Returns true if the namespace was recognised, false otherwise.
     */
    public boolean handleEvent(
            final Jid from, final String node, final String itemId, final Extension payload) {
        if (Namespace.X3DHPQ_DEVICELIST.equals(node)) {
            if (payload instanceof DeviceList) {
                handleInboundDeviceList(from, (DeviceList) payload);
                // also dispatch to optional listener (e.g. UI layer)
                if (deviceListListener != null) {
                    deviceListListener.onDeviceListReceived(from, (DeviceList) payload);
                }
            }
            return true;
        } else if (Namespace.X3DHPQ_BUNDLE.equals(node)) {
            if (payload instanceof Bundle) {
                int deviceId = parseDeviceId(itemId);
                handleInboundBundle(from, deviceId, (Bundle) payload);
                if (bundleListener != null) {
                    bundleListener.onBundleReceived(from, deviceId, (Bundle) payload);
                }
            }
            return true;
        } else if (Namespace.X3DHPQ_AUDIT.equals(node)) {
            if (payload instanceof AuditEntry) {
                handleInboundAuditEntry(from, itemId, (AuditEntry) payload);
                if (auditListener != null) {
                    auditListener.onAuditEntryReceived(from, itemId, (AuditEntry) payload);
                }
            }
            return true;
        } else if (Namespace.X3DHPQ_GROUP.equals(node)) {
            if (payload instanceof MembershipEntry && membershipListener != null) {
                membershipListener.onMembershipEntryReceived(from, itemId, (MembershipEntry) payload);
            }
            return true;
        } else if (Namespace.X3DHPQ_RECOVERY.equals(node)) {
            if (payload instanceof Recovery && recoveryListener != null) {
                recoveryListener.onRecoveryReceived(from, (Recovery) payload);
            }
            return true;
        } else if (Namespace.X3DHPQ_PAIR.equals(node)) {
            // Serverless rendezvous (§10.1a, method B): a <pair-hello> published to our own PEP
            // node reaches this (existing) resource via self-PEP +notify. Hand it to the pairing
            // trigger — the same code path a directed pair-hello message uses.
            if (payload instanceof im.conversations.android.xmpp.model.x3dhpq.pair.PairHello
                    && account != null
                    && account.getXmppConnection() != null) {
                account.getXmppConnection()
                        .getManager(
                                eu.siacs.conversations.xmpp.manager.VerifyDeviceManager.class)
                        .handlePairHello(
                                (im.conversations.android.xmpp.model.x3dhpq.pair.PairHello) payload);
            }
            return true;
        }
        return false;
    }

    /**
     * Handles all items from a PEP Items notification for x3dhpq nodes.
     * Called by X3dhpqManager when the PubSubManager routes a matching node event.
     */
    public void handleItems(final Jid from, final Items items) {
        final String node = items.getNode();
        if (Namespace.X3DHPQ_DEVICELIST.equals(node)) {
            final var entry = items.getFirstItemWithId(DeviceList.class);
            if (entry != null) {
                handleEvent(from, node, entry.getKey(), entry.getValue());
            }
        } else if (Namespace.X3DHPQ_BUNDLE.equals(node)) {
            final var entry = items.getFirstItemWithId(Bundle.class);
            if (entry != null) {
                handleEvent(from, node, entry.getKey(), entry.getValue());
            }
        } else if (Namespace.X3DHPQ_AUDIT.equals(node)) {
            // audit nodes may carry multiple entries; dispatch each
            for (final var e : items.getItemMap(AuditEntry.class).entrySet()) {
                handleEvent(from, node, e.getKey(), e.getValue());
            }
        } else if (Namespace.X3DHPQ_GROUP.equals(node)) {
            for (final var e : items.getItemMap(MembershipEntry.class).entrySet()) {
                handleEvent(from, node, e.getKey(), e.getValue());
            }
        } else if (Namespace.X3DHPQ_RECOVERY.equals(node)) {
            final var entry = items.getFirstItemWithId(Recovery.class);
            if (entry != null) {
                handleEvent(from, node, entry.getKey(), entry.getValue());
            }
        } else if (Namespace.X3DHPQ_PAIR.equals(node)) {
            final var entry =
                    items.getFirstItemWithId(
                            im.conversations.android.xmpp.model.x3dhpq.pair.PairHello.class);
            if (entry != null) {
                handleEvent(from, node, entry.getKey(), entry.getValue());
            }
        } else {
            Log.d(Config.LOGTAG, getLogprefix() + "ignoring unrecognised x3dhpq node: " + node);
        }
    }

    /**
     * The four +notify features are declared statically in DiscoManager.getServiceDescription().
     * This method exists as the documented call site for stream-negotiated initialisation;
     * no runtime action is needed here in C3.
     */
    public void registerNotifyFeatures() {
        // features are advertised via DiscoManager static list; nothing to do at runtime
    }

    /**
     * Sends an explicit XEP-0060 subscribe IQ to roomJid for the group:0 node.
     * Required because the Wave 5a server tracks explicit subscriptions for room nodes.
     */
    public void subscribeToRoomGroupNode(final Jid roomJid) {
        final Iq packet =
                mXmppConnectionService
                        .getIqGenerator()
                        .generatePubSubSubscription(
                                roomJid,
                                Namespace.X3DHPQ_GROUP,
                                account.getJid().asBareJid());
        mXmppConnectionService.sendIqPacket(
                account,
                packet,
                response -> {
                    if (response.getType() == Iq.Type.RESULT) {
                        Log.d(
                                Config.LOGTAG,
                                getLogprefix()
                                        + "subscribed to group:0 node on "
                                        + roomJid);
                    } else {
                        Log.d(
                                Config.LOGTAG,
                                getLogprefix()
                                        + "failed to subscribe to group:0 node on "
                                        + roomJid
                                        + ": "
                                        + response);
                    }
                });
    }

    /**
     * Publishes the local DeviceList and the local Bundle for the active deviceId.
     * Idempotent: PEP dedupes by item id; we re-publish on every login (cheap).
     */
    public void publishLocalState() {
        if (db == null || account == null || mXmppConnectionService == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": publishLocalState called without db/account");
            return;
        }
        // One-shot: wipe stored pairwise sessions on first run after the
        // ratchet bootstrap fix (initiator/responder pre-ratchet). Sessions
        // serialised before the fix used the lazy chainSendKey=rootKey[32:64]
        // format which the responder side cannot reproduce, so every cached
        // session would fail to decrypt the very first message after the
        // upgrade. The flag below is permanent (one wipe per install) so
        // we don't keep deleting healthy sessions across restarts.
        try {
            final android.content.SharedPreferences prefs =
                    androidx.preference.PreferenceManager.getDefaultSharedPreferences(
                            mXmppConnectionService);
            final String flagKey = "x3dhpq_session_wipe_v1_" + account.getUuid();
            if (!prefs.getBoolean(flagKey, false)) {
                final int wiped = mXmppConnectionService.databaseBackend
                        .wipeAllX3dhpqSessions(account.getUuid());
                Log.i(Config.LOGTAG, LOGPREFIX
                        + ": wiped " + wiped + " stale x3dhpq_session rows; sessions will re-establish on next send");
                prefs.edit().putBoolean(flagKey, true).apply();
            }
        } catch (Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": session wipe-v1 failed: " + e.getMessage());
        }

        // §10.6.1 fresh-device gating: a device that only has device-level material
        // (DIK, no AIK yet — LocalKeyBootstrap#ensureBootstrapped left it pending)
        // must not publish an authoritative devicelist or act as primary. Resolve the
        // pending state against the account's own devicelist first.
        if (isPendingEnrollment()) {
            resolvePendingEnrollment();
            return;
        }

        publishDeviceList();
        publishOwnBundle();
    }

    /**
     * §10.6.4b: the explicit, user-chosen "generate a new identity instead" override
     * from the pending-enrollment registration-choice UX. Destructive — see {@link
     * LocalKeyBootstrap#mintFreshIdentity}. Only meaningful while {@link
     * #isPendingEnrollment()} is true; the caller (UI) is expected to have already
     * shown the destructive-action warning from §10.6.4b before invoking this.
     */
    public void generateNewIdentity() {
        if (db == null || account == null || mXmppConnectionService == null) return;
        final LocalKeyBootstrap bootstrap = new LocalKeyBootstrap(mXmppConnectionService.databaseBackend);
        final LocalKeyBootstrap.BootstrapResult result = bootstrap.mintFreshIdentity(account.getUuid());
        Log.i(Config.LOGTAG, LOGPREFIX + ": " + account.getJid().asBareJid()
                + " explicitly generated a NEW identity (§10.6.4b), fp=" + result.fingerprint);
        if (!result.pendingEnrollment) {
            publishDeviceList();
            publishOwnBundle();
        }
    }

    /** True if this install's local device is still in §10.6.1 pending-enrollment (DIK, no AIK). */
    public boolean isPendingEnrollment() {
        if (db == null || account == null) return false;
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows =
                db.listX3dhpqLocalDevices(account.getUuid());
        if (rows.isEmpty()) return false;
        return LocalKeyBootstrap.isPending(rows.get(0));
    }

    /**
     * Resolves a §10.6.1 pending-enrollment device: fetches the account's own devicelist
     * from the server. An EMPTY (or absent/error, e.g. {@code item-not-found}) response
     * means no AIK has ever been published for this account anywhere — this is genuinely
     * the first device, so it is promoted to primary and its (now signed) devicelist is
     * published. A NON-empty response means an existing primary already owns this
     * account's AIK — this device remains pending, publishes nothing, and waits to be
     * confirmed via CPace pairing (§10.6.2), which installs a primary-issued AIK/DC and
     * clears the pending state (see {@code PairToExistingActivity#installPairingResult}).
     */
    private void resolvePendingEnrollment() {
        if (db == null || account == null || mXmppConnectionService == null) return;
        final Jid ownBareJid = account.getJid().asBareJid();
        Log.d(Config.LOGTAG, LOGPREFIX
                + ": pending-enrollment — checking " + ownBareJid
                + "'s own devicelist before minting an AIK (§10.6.1)");
        final Iq iq =
                mXmppConnectionService
                        .getIqGenerator()
                        .generateX3dhpqRequestDeviceList(ownBareJid);
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    boolean accountHasExistingIdentity = false;
                    if (response.getType() == Iq.Type.RESULT) {
                        final Extension payload = extractPubsubPayload(response, DeviceList.class);
                        accountHasExistingIdentity =
                                payload instanceof DeviceList
                                        && !((DeviceList) payload).getDevices().isEmpty();
                    }
                    // Re-check pending state: a concurrent pairing may have already
                    // confirmed this device while the fetch was in flight.
                    if (!isPendingEnrollment()) {
                        Log.d(Config.LOGTAG, LOGPREFIX
                                + ": pending-enrollment resolved concurrently (pairing"
                                + " confirmation arrived first); nothing to do");
                        return;
                    }
                    if (accountHasExistingIdentity) {
                        Log.i(Config.LOGTAG, LOGPREFIX
                                + ": account " + ownBareJid + " already has a published"
                                + " identity — remaining pending-enrollment, awaiting"
                                + " confirmation by an existing device (§10.6)");
                        // Stays pending. No publish. UX: X3dhpqSelfDevicesActivity surfaces
                        // this state and offers the explicit "generate a new identity
                        // instead" override (§10.6.4b) via LocalKeyBootstrap#mintFreshIdentity.
                    } else {
                        Log.i(Config.LOGTAG, LOGPREFIX
                                + ": no existing identity found for " + ownBareJid
                                + " — genuinely the first device; minting AIK and becoming"
                                + " primary");
                        final LocalKeyBootstrap bootstrap =
                                new LocalKeyBootstrap(mXmppConnectionService.databaseBackend);
                        final LocalKeyBootstrap.BootstrapResult result =
                                bootstrap.promoteToPrimary(account.getUuid());
                        if (!result.pendingEnrollment) {
                            publishDeviceList();
                            publishOwnBundle();
                        }
                    }
                });
    }

    /** Sends a fetch IQ for the peer's devicelist; response is processed by handleInboundDeviceList. */
    public void requestPeerDeviceList(final Jid peerBareJid) {
        if (mXmppConnectionService == null) return;
        final Iq iq =
                mXmppConnectionService
                        .getIqGenerator()
                        .generateX3dhpqRequestDeviceList(peerBareJid.asBareJid());
        Log.d(Config.LOGTAG, "x3dhpq: -> sending devicelist fetch IQ to " + peerBareJid + ": " + iq);
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    Log.d(Config.LOGTAG,
                            "x3dhpq: <- devicelist fetch response from " + peerBareJid
                                    + " type=" + response.getType() + " xml="
                                    + StreamElementWriter.asStringUnchecked(response));
                    if (response.getType() != Iq.Type.RESULT) {
                        Log.w(Config.LOGTAG,
                                "x3dhpq: devicelist fetch returned non-RESULT for " + peerBareJid);
                        return;
                    }
                    final Extension payload = extractPubsubPayload(response, DeviceList.class);
                    if (payload == null) {
                        Log.w(Config.LOGTAG,
                                "x3dhpq: devicelist fetch RESULT carried no DeviceList payload"
                                        + " for " + peerBareJid + "; iq body=" + response);
                        return;
                    }
                    handleInboundDeviceList(peerBareJid, (DeviceList) payload);
                });
    }

    /** Sends a fetch IQ for a specific peer device bundle; response is processed by handleInboundBundle. */
    public void requestPeerBundle(final Jid peerBareJid, final int deviceId) {
        if (mXmppConnectionService == null) return;
        final Iq iq =
                mXmppConnectionService
                        .getIqGenerator()
                        .generateX3dhpqRequestBundle(peerBareJid.asBareJid(), deviceId);
        Log.d(Config.LOGTAG,
                "x3dhpq: -> sending bundle fetch IQ to " + peerBareJid + "/" + deviceId
                        + ": " + iq);
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    Log.d(Config.LOGTAG,
                            "x3dhpq: <- bundle fetch response from " + peerBareJid + "/" + deviceId
                                    + " type=" + response.getType() + " body=" + response);
                    if (response.getType() != Iq.Type.RESULT) {
                        Log.w(Config.LOGTAG,
                                "x3dhpq: bundle fetch returned non-RESULT for "
                                        + peerBareJid + "/" + deviceId);
                        return;
                    }
                    final Extension payload = extractPubsubPayload(response, Bundle.class);
                    if (payload == null) {
                        Log.w(Config.LOGTAG,
                                "x3dhpq: bundle fetch RESULT carried no Bundle payload for "
                                        + peerBareJid + "/" + deviceId + "; iq body=" + response);
                        return;
                    }
                    handleInboundBundle(peerBareJid, deviceId, (Bundle) payload);
                });
    }

    /**
     * Handles an inbound devicelist: enforces the hybrid-signature + monotonic
     * version gate (§8.2/§8.5), then persists remote_device rows and schedules
     * missing bundle fetches. The {@code <sig>}/{@code <mldsa-sig>} are read from
     * the last children of the {@code <devicelist>} element (§8.4).
     */
    void handleInboundDeviceList(final Jid peerBareJid, final DeviceList list) {
        if (db == null) return;
        final String accountUuid = account != null ? account.getUuid() : "test";
        final String peer = peerBareJid.asBareJid().toString();
        final long now = System.currentTimeMillis() / 1000L;

        // §8.2/§8.5 gate: reject rollback/fork/downgrade/bad-signature lists
        // before trusting any of their contents.
        if (!deviceListGate(accountUuid, peer, list, now)) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: REJECTED inbound devicelist from " + peer + " (see gate log)");
            return;
        }

        // Self-heal (mirrors Dino): x3dhpq_co_account_device has exactly one
        // writer elsewhere in this class (the pairing UI, when acting as the
        // existing/primary side), so a newly-paired non-primary device starts
        // with an EMPTY co-account table and would otherwise clobber the
        // account's devicelist with a self-only one on its next publish
        // (§8.2). Fix: whenever we receive the account's OWN authoritative
        // devicelist, remember every sibling device (i.e. every entry that
        // isn't this install's own local device) in x3dhpq_co_account_device
        // so publishDeviceList() — which unions x3dhpq_local_device with
        // x3dhpq_co_account_device — republishes the full list intact.
        final boolean isOwnList =
                account != null && peerBareJid.asBareJid().equals(account.getJid().asBareJid());
        final java.util.Set<Integer> localIds = new java.util.HashSet<>();
        if (isOwnList) {
            for (final DatabaseBackend.X3dhpqLocalDeviceRow row :
                    db.listX3dhpqLocalDevices(accountUuid)) {
                localIds.add(row.deviceId());
            }
        }
        // §10.6.3 trust gating: a sibling appearing in our own devicelist is only
        // auto-trusted as a co-account device if it is covered by a valid, AIK-signed
        // AddDevice audit entry (§11.4) — never by devicelist presence alone (that
        // would let a rogue self-addition go silently trusted).
        final java.util.Set<Integer> chainConfirmedIds =
                isOwnList ? verifiedAddDeviceIds(accountUuid, peer) : java.util.Collections.emptySet();

        final Collection<Device> devices = list.getDevices();
        Log.d(Config.LOGTAG,
                "x3dhpq: handleInboundDeviceList for " + peer
                        + " — list contains " + devices.size() + " device(s); xml="
                        + StreamElementWriter.asStringUnchecked(list));
        final java.util.Set<Integer> liveIds = new java.util.HashSet<>();
        final java.util.Set<Integer> coAccountLiveIds = new java.util.HashSet<>();
        for (final Device device : devices) {
            final Integer id = device.getDeviceId();
            final Cert certEl = device.getCert();
            final byte[] dcBytes = certEl != null ? certEl.asBytes() : null;
            final Long addedAt = device.getAddedAt(); // §8.4 — needed to rebuild the SignedPart
            Log.d(Config.LOGTAG,
                    "x3dhpq: device entry id=" + id
                            + " addedAt=" + addedAt
                            + " hasCert=" + (certEl != null)
                            + " dcLen=" + (dcBytes == null ? -1 : dcBytes.length));
            if (id == null) {
                Log.w(Config.LOGTAG, "x3dhpq: device entry has null id, skipping");
                continue;
            }
            if (dcBytes == null || dcBytes.length == 0) {
                Log.w(Config.LOGTAG, "x3dhpq: device " + id + " has no cert content, skipping");
                continue;
            }

            try {
                // parse DC to validate it is well-formed before persisting
                DeviceCertificate.unmarshal(dcBytes);
                db.putX3dhpqRemoteDevice(accountUuid, peer, id, dcBytes, now);
                liveIds.add(id);
                Log.d(Config.LOGTAG,
                        "x3dhpq: stored remote_device for " + peer + "/" + id);

                if (isOwnList && !localIds.contains(id)) {
                    if (chainConfirmedIds.contains(id)) {
                        final long deviceAddedAt = addedAt != null ? addedAt : now;
                        int flags;
                        try {
                            flags = Integer.parseInt(
                                    com.google.common.base.Strings.nullToEmpty(device.getFlags())
                                            .trim());
                        } catch (final NumberFormatException nfe) {
                            flags = 0;
                        }
                        db.putX3dhpqCoAccountDevice(accountUuid, id, dcBytes, deviceAddedAt, flags);
                        coAccountLiveIds.add(id);
                        Log.d(Config.LOGTAG,
                                "x3dhpq: stored co_account_device for " + peer + "/" + id
                                        + " (self-heal, audit-chain confirmed)");
                    } else {
                        // §10.6.3: NOT covered by a valid AddDevice audit entry — do not
                        // silently trust. Leaving it out of coAccountLiveIds also means the
                        // pruneX3dhpqCoAccountDevicesNotIn call below will drop it if it was
                        // (wrongly) trusted before this check existed.
                        Log.w(Config.LOGTAG,
                                "x3dhpq: sibling device " + id + " appears in own devicelist"
                                        + " but has NO valid AddDevice audit entry —"
                                        + " NOT auto-trusting (§10.6.3); surfacing as a"
                                        + " pending/unconfirmed security event");
                        surfaceUnconfirmedSiblingEvent(id);
                    }
                }
            } catch (Exception e) {
                Log.w(Config.LOGTAG,
                        "x3dhpq: malformed peer DC from " + peer + "/" + id + ": " + e.getMessage());
                continue;
            }

            // schedule bundle fetch if we have no stored bundle for this device yet
            if (db.loadX3dhpqRemoteBundle(accountUuid, peer, id) == null
                    && mXmppConnectionService != null) {
                Log.d(Config.LOGTAG,
                        "x3dhpq: scheduling bundle fetch for " + peer + "/" + id);
                requestPeerBundle(peerBareJid, id);
            }
        }
        // The published devicelist is authoritative. Drop any cached
        // x3dhpq_remote_device / bundle / session rows for this peer whose
        // device id is no longer in the list — otherwise we keep sending
        // pairwise envelopes (e.g. SenderChainAnnouncements) to ghost
        // device ids that the peer regenerated and abandoned.
        db.pruneX3dhpqRemoteDevicesNotIn(accountUuid, peer, liveIds);
        if (isOwnList) {
            // Same reasoning for the co-account self-heal set: a device the
            // account itself dropped from its authoritative list must not
            // resurrect on our next publish.
            db.pruneX3dhpqCoAccountDevicesNotIn(accountUuid, coAccountLiveIds);
            // Accepting the account's OWN authoritative devicelist re-baselines the
            // shrink guard's committed set (publishDeviceList) to exactly what we
            // just accepted, so a legitimate remote removal does not later look
            // like an unauthorized shrink and block our next publish.
            db.putX3dhpqCommittedDevices(accountUuid, liveIds);
        }
    }

    /**
     * The signature + monotonic-version gate for an inbound devicelist (§8.2/§8.5).
     *
     * <p>Returns {@code true} when the list may be processed (accepted, or a signed
     * list whose signature check is DEFERRED because the peer AIK is not yet known),
     * {@code false} when it MUST be rejected (rollback, fork, bad signature, or an
     * unsigned/legacy list after a signed one was already accepted — downgrade lock).
     */
    private boolean deviceListGate(
            final String accountUuid, final String peer, final DeviceList list, final long now) {
        // <sig>/<mldsa-sig> are the last children of <devicelist> (§8.4).
        final Sig sigEl = list.getSig();
        final MldsaSig mldsaEl = list.getMldsaSig();
        final byte[] edSig = sigEl != null ? sigEl.asBytes() : null;
        final byte[] mldsaSig = mldsaEl != null ? mldsaEl.asBytes() : null;
        final boolean hasSig =
                edSig != null && edSig.length > 0 && mldsaSig != null && mldsaSig.length > 0;

        final long issuedAt = parseLongOr(list.getIssuedAt(), 0L);
        // Clock-skew guard (§8.5): reject lists issued too far in the future.
        if (issuedAt > now + 300L) {
            Log.w(Config.LOGTAG, "x3dhpq: devicelist from " + peer
                    + " issued_at " + issuedAt + " > now+300s; rejecting");
            return false;
        }

        final DatabaseBackend.X3dhpqDeviceListStateRow state =
                db.loadX3dhpqDeviceListState(accountUuid, peer);
        final boolean everAcceptedSigned = state != null && state.acceptedSigned();

        if (!hasSig) {
            // Transitional rule (§8.5): accept an unsigned list ONLY if we have
            // never accepted a signed one for this account; otherwise a malicious
            // server could strip signatures to force a downgrade.
            if (everAcceptedSigned) {
                Log.w(Config.LOGTAG, "x3dhpq: unsigned devicelist from " + peer
                        + " rejected — a signed list was already accepted (downgrade lock)");
                return false;
            }
            Log.d(Config.LOGTAG, "x3dhpq: accepting unsigned (transitional) devicelist from " + peer);
            return true;
        }

        // Signed list. We need the peer AIK to verify.
        AccountIdentityPub peerAik = resolvePinnedPeerAik(accountUuid, peer);
        final boolean isOwnList =
                account != null && peer.equals(account.getJid().asBareJid().toString());
        if (peerAik == null && isOwnList) {
            // Our OWN devicelist must verify against our CURRENT AIK — never
            // deferred. After an identity reset the server still serves the
            // pre-reset list (signed by the OLD AIK, listing devices certified by
            // it); verifying against our own AIK rejects that stale list here
            // instead of self-healing its dead devices back into our published
            // list, which would otherwise present two devices under two different
            // AIKs to contacts (breaking their signature verification).
            final DatabaseBackend.X3dhpqAccountIdentityRow ownRow =
                    db.loadX3dhpqAccountIdentity(accountUuid);
            if (ownRow != null) {
                try {
                    peerAik = AccountIdentityPub.unmarshal(ownRow.aikPub());
                } catch (final Exception ex) {
                    peerAik = null;
                }
            }
        }
        if (peerAik == null) {
            // First-contact caveat: bundle (hence AIK) not fetched yet. Defer the
            // gate — process the list so bundle fetches are scheduled; a later
            // republish will be verified once the AIK is known.
            Log.d(Config.LOGTAG, "x3dhpq: deferring devicelist signature gate for " + peer
                    + " — peer AIK not yet known");
            return true;
        }

        final long version = parseUnsignedLongOr(list.getVersion(), -1L);
        if (version < 0) {
            Log.w(Config.LOGTAG, "x3dhpq: signed devicelist from " + peer
                    + " has no/invalid version; rejecting");
            return false;
        }

        // Reconstruct the §8.3 SignedPart from the wire (sorted by device_id asc)
        // and verify BOTH AIK signatures + every embedded DC.
        final List<im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> entries =
                coreEntriesFromWire(list);
        if (entries == null) {
            Log.w(Config.LOGTAG, "x3dhpq: signed devicelist from " + peer
                    + " has a malformed device/cert; cannot verify, rejecting");
            return false;
        }
        for (final im.conversations.x3dhpq.types.DeviceList.DeviceListEntry e : entries) {
            final byte[] dcSigned = e.getCert().signedPart();
            final boolean dcEd = X3dhpqCrypto.ed25519Verify(
                    peerAik.getPubEd25519(), dcSigned, e.getCert().getSigEd25519());
            final boolean dcMl = X3dhpqCrypto.mldsa65Verify(
                    peerAik.getPubMLDSA(), dcSigned, e.getCert().getSigMLDSA());
            if (!dcEd || !dcMl) {
                Log.w(Config.LOGTAG, "x3dhpq: devicelist from " + peer
                        + " embeds a DC not signed by the peer AIK; rejecting");
                return false;
            }
        }

        final byte[] signedPart = deviceListSignedPart(version, issuedAt, entries);
        final boolean edOk = X3dhpqCrypto.ed25519Verify(peerAik.getPubEd25519(), signedPart, edSig);
        final boolean mlOk = X3dhpqCrypto.mldsa65Verify(peerAik.getPubMLDSA(), signedPart, mldsaSig);
        if (!edOk || !mlOk) {
            Log.w(Config.LOGTAG, "x3dhpq: devicelist AIK signature FAILED for " + peer
                    + " (ed=" + edOk + " mldsa=" + mlOk + "); rejecting");
            // §10.6.5: a signed devicelist that fails to verify against the AIK we have
            // TOFU-pinned for this peer (as opposed to the "peerAik == null, first
            // contact" deferred path above) looks like a silent AIK reconstruction —
            // never auto-accept it. Flag it as a security event requiring explicit
            // user re-trust instead of just silently dropping the stanza. Skip this
            // for our OWN account's list (isOwnList): a stale pre-reset self-list
            // failing against our current AIK is a different (self, not peer) scenario,
            // already logged distinctly above.
            if (!isOwnList) {
                try {
                    flagIdentityReconstructionEvent(eu.siacs.conversations.xmpp.Jid.of(peer));
                } catch (final Exception ignored) {
                    // best-effort UX signal; never let it block the reject decision above
                }
            }
            return false;
        }

        // Version rule (§8.5): reject rollback and same-version forks; an identical
        // republish at the same version is an idempotent no-op.
        final long lastSeenVersion = state != null ? state.version() : -1L;
        final byte[] contentHash = deviceListContentHash(entries);
        if (version < lastSeenVersion) {
            Log.w(Config.LOGTAG, "x3dhpq: devicelist rollback from " + peer
                    + " (version " + version + " < last-seen " + lastSeenVersion + "); rejecting");
            return false;
        }
        if (version == lastSeenVersion
                && state != null
                && !Arrays.equals(state.contentHash(), contentHash)) {
            Log.w(Config.LOGTAG, "x3dhpq: devicelist fork from " + peer
                    + " (same version " + version + ", different content); rejecting");
            return false;
        }

        db.putX3dhpqDeviceListState(accountUuid, peer, version, contentHash, true, now);
        Log.d(Config.LOGTAG, "x3dhpq: accepted signed devicelist from " + peer
                + " version=" + version);
        return true;
    }

    /**
     * Builds sorted (device_id ascending, unsigned) core entries from an inbound
     * XML devicelist for SignedPart reconstruction; returns null if any device is
     * missing its id/added-at/cert or the cert is unparseable.
     */
    private static List<im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> coreEntriesFromWire(
            final DeviceList list) {
        final List<im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> entries =
                new ArrayList<>();
        for (final Device device : list.getDevices()) {
            final Integer id = device.getDeviceId();
            final Long addedAt = device.getAddedAt();
            final Cert certEl = device.getCert();
            final byte[] dcBytes = certEl != null ? certEl.asBytes() : null;
            if (id == null || addedAt == null || dcBytes == null || dcBytes.length == 0) {
                return null;
            }
            final byte flags;
            try {
                flags = (byte) Integer.parseInt(
                        com.google.common.base.Strings.nullToEmpty(device.getFlags()).trim());
            } catch (final NumberFormatException e) {
                return null;
            }
            final DeviceCertificate cert;
            try {
                cert = DeviceCertificate.unmarshal(dcBytes);
            } catch (final Exception e) {
                return null;
            }
            // Retain the verbatim base64-decoded <cert> bytes as received; the verify
            // path must reconstruct the SignedPart over these exact bytes (§8.4), not
            // over a re-marshaled cert. The parsed cert is kept for DC verify (§7.3).
            entries.add(new im.conversations.x3dhpq.types.DeviceList.DeviceListEntry(
                    id & 0xffffffffL, addedAt, flags, cert, dcBytes));
        }
        entries.sort(java.util.Comparator.comparingLong(
                im.conversations.x3dhpq.types.DeviceList.DeviceListEntry::getDeviceId));
        return entries;
    }

    /** Resolves the pinned (TOFU) peer AIK from any cached bundle, or null if none. */
    private AccountIdentityPub resolvePinnedPeerAik(final String accountUuid, final String peer) {
        for (final DatabaseBackend.X3dhpqRemoteDeviceRow rd :
                db.listX3dhpqRemoteDevices(accountUuid, peer)) {
            final DatabaseBackend.X3dhpqRemoteBundleRow b =
                    db.loadX3dhpqRemoteBundle(accountUuid, peer, rd.deviceId());
            if (b != null && b.aikPubMarshal() != null) {
                try {
                    return AccountIdentityPub.unmarshal(b.aikPubMarshal());
                } catch (final Exception ignored) {
                    // try the next cached bundle
                }
            }
        }
        return null;
    }

    private static long parseLongOr(final String s, final long dflt) {
        if (s == null) return dflt;
        try {
            return Long.parseLong(s.trim());
        } catch (final NumberFormatException e) {
            return dflt;
        }
    }

    private static long parseUnsignedLongOr(final String s, final long dflt) {
        if (s == null) return dflt;
        try {
            return Long.parseUnsignedLong(s.trim());
        } catch (final NumberFormatException e) {
            return dflt;
        }
    }

    /** Handles an inbound bundle: verifies DC signatures, pins AIK (TOFU), and persists. */
    void handleInboundBundle(final Jid peerBareJid, final int deviceId, final Bundle bundle) {
        if (db == null) return;
        final String accountUuid = account != null ? account.getUuid() : "test";
        final String peer = peerBareJid.asBareJid().toString();

        final AikEd25519 aikEdEl = bundle.getAikEd25519();
        final AikMldsa aikMlEl = bundle.getAikMldsa();
        final Dc dcEl = bundle.getDc();
        if (aikEdEl == null || aikMlEl == null || dcEl == null) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: incomplete bundle from " + peer + "/" + deviceId);
            return;
        }

        final byte[] aikEdBytes = aikEdEl.asBytes();
        final byte[] aikMlBytes = aikMlEl.asBytes();
        final byte[] dcBytes = dcEl.asBytes();

        // build AccountIdentityPub from the two AIK halves
        final AccountIdentityPub aip;
        try {
            aip = new AccountIdentityPub(aikEdBytes, aikMlBytes);
        } catch (Exception e) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: invalid AIK in bundle from " + peer + "/" + deviceId + ": " + e.getMessage());
            return;
        }
        final byte[] aipMarshal = aip.marshal();

        // TOFU pin check: if a bundle row already exists with a different AIK, refuse to overwrite
        final DatabaseBackend.X3dhpqRemoteBundleRow existing =
                db.loadX3dhpqRemoteBundle(accountUuid, peer, deviceId);
        if (existing != null && !Arrays.equals(existing.aikPubMarshal(), aipMarshal)) {
            Log.e(Config.LOGTAG,
                    "x3dhpq: AIK MISMATCH for " + peer + "/" + deviceId
                    + " — possible compromise or rotation; refusing to overwrite."
                    + " (Wave F surfaces this in UI.)");
            return;
        }

        // parse and verify DC
        final DeviceCertificate dc;
        try {
            dc = DeviceCertificate.unmarshal(dcBytes);
        } catch (Exception e) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: malformed DC in bundle from " + peer + "/" + deviceId);
            return;
        }

        // Verify against the bare signedPart() bytes (no prefix); see LocalKeyBootstrap
        // for rationale. Matches Go reference + dino-fork.
        final byte[] signedPart = dc.signedPart();
        final boolean edOK = X3dhpqCrypto.ed25519Verify(aikEdBytes, signedPart, dc.getSigEd25519());
        final boolean mlOK = X3dhpqCrypto.mldsa65Verify(aikMlBytes, signedPart, dc.getSigMLDSA());
        if (!edOK || !mlOK) {
            Log.e(Config.LOGTAG,
                    "x3dhpq: DC verification FAILED for " + peer + "/" + deviceId
                    + " (ed=" + edOK + " mldsa=" + mlOK + ")");
            return;
        }

        // verify deviceId in DC matches the bundle's item id
        if ((int) dc.getDeviceId() != deviceId) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: bundle/DC deviceId mismatch: bundle=" + deviceId
                    + " dc=" + dc.getDeviceId());
            return;
        }

        // serialise the bundle extension to XML bytes for storage
        final byte[] bundleXml = serialiseBundleToXml(bundle);

        final long now = System.currentTimeMillis() / 1000L;
        db.putX3dhpqRemoteBundle(accountUuid, peer, deviceId, aipMarshal, bundleXml, now);

        Log.d(Config.LOGTAG,
                "x3dhpq: stored bundle for " + peer + "/" + deviceId
                + ", aik fp=" + aip.fingerprint(X3dhpqCrypto.BLAKE2B_160));

        // A previously WAITING outbound message may now be sendable. Find any
        // pending messages for this peer's conversation and kick off a resend.
        // Without this hook, the user has to manually resend after the bundle
        // arrives — which causes the symptom "messages don't go and there is
        // nothing in the logs" since preparePayloadMessage silently returns null.
        if (mXmppConnectionService != null && account != null) {
            final eu.siacs.conversations.entities.Conversation conversation =
                    mXmppConnectionService.find(account, peerBareJid.asBareJid());
            if (conversation != null) {
                Log.d(Config.LOGTAG,
                        "x3dhpq: triggering resend of WAITING messages for "
                                + peer + " after bundle arrival");
                mXmppConnectionService.sendUnsentMessages(conversation);
            }
            // Drain any group journal publishes that were waiting on this
            // peer's AIK to land in the bundle store.
            final var gcs = mXmppConnectionService.getGroupCryptoService(account);
            if (gcs != null) {
                gcs.onPeerBundleArrived(peerBareJid);
            }
        }
    }

    /**
     * Attempts to establish an outbound (initiator) PQXDH session with a peer device.
     * Returns empty if the peer bundle is not yet in the database (a fetch is kicked off);
     * caller should retry when the bundle arrives.
     */
    public Optional<PqxdhResult> establishOutboundSession(
            final Jid peerBareJid, final int peerDeviceId) {
        if (db == null) return Optional.empty();
        final String accountUuid = account != null ? account.getUuid() : "test";
        final String peer = peerBareJid.asBareJid().toString();

        // Load peer bundle; kick off a fetch and return empty if missing.
        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                db.loadX3dhpqRemoteBundle(accountUuid, peer, peerDeviceId);
        if (row == null || row.bundleXml() == null || row.bundleXml().length == 0) {
            requestPeerBundle(peerBareJid, peerDeviceId);
            return Optional.empty();
        }

        // Parse the stored XML bytes back into a Bundle extension, then into BundleData.
        final BundleData peerBundle;
        try {
            final Bundle bundleExt = parseBundleXml(row.bundleXml());
            peerBundle = BundleParser.fromBundle(bundleExt);
        } catch (Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": failed to parse stored bundle for "
                    + peer + "/" + peerDeviceId + ": " + e.getMessage());
            return Optional.empty();
        }

        // Load our DIK.
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": no local device row for " + accountUuid);
            return Optional.empty();
        }
        final DatabaseBackend.X3dhpqLocalDeviceRow localRow = localRows.get(0);
        final DeviceIdentityKey dik = DeviceIdentityKey.unmarshal(localRow.dikPriv());

        // Load our AIK for the envelope.
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(accountUuid);
        final byte[] aikEdPub = aikRow != null
                ? AccountIdentityPub.unmarshal(aikRow.aikPub()).getPubEd25519() : new byte[32];
        final byte[] aikMlPub = aikRow != null
                ? AccountIdentityPub.unmarshal(aikRow.aikPub()).getPubMLDSA() : new byte[1952];

        // Run initiator.
        final PqxdhResult result = PqxdhInitiator.initiate(
                dik.getPrivX25519(),
                dik.getPubX25519(),
                dik.getPubEd25519(),
                localRow.dc(),
                aikEdPub,
                aikMlPub,
                peerBundle,
                X3dhpqCrypto.HKDF_SHA512);

        // Persist session state. The initiator MUST pre-ratchet against the
        // peer's SPK pub; the responder side (dino's new_receiving_state +
        // first-decrypt dh_ratchet_step) derives chainRecvKey from
        // dh_ratchet_step(rk, peer_SPK_priv, our_eph_pub, zeros). ECDH
        // symmetry makes that equal to dh_ratchet_step(rk, our_eph_priv,
        // peer_SPK_pub, zeros) on our side. Using the lazy fromPqxdh()
        // factory left chainSendKey at rootKey[32:64], which the responder
        // never sees, so the AES-GCM tag mismatched on every first message
        // and decryption returned wolfSSL rc=-180.
        final long now = System.currentTimeMillis() / 1000L;
        db.putX3dhpqSession(accountUuid, peer, peerDeviceId,
                serialiseInitiatorSession(result, peerBundle.spkPub), now);

        return Optional.of(result);
    }

    /**
     * Accepts an inbound (responder) PQXDH session from a peer's prekey envelope.
     * The consumed OPK (if any) is marked so the bundle is refreshed.
     */
    public PqxdhResult acceptInboundSession(
            final Jid peerBareJid, final int peerDeviceId, final PrekeyEnvelope env) {
        final String accountUuid = account != null ? account.getUuid() : "test";
        final String peer = peerBareJid.asBareJid().toString();

        // Load our DIK.
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) {
            throw new IllegalStateException("no local device row for " + accountUuid);
        }
        final DeviceIdentityKey dik = DeviceIdentityKey.unmarshal(localRows.get(0).dikPriv());

        // Load our SPK.
        final DatabaseBackend.X3dhpqSignedPreKeyRow spkRow =
                db.loadLatestX3dhpqSignedPreKey(accountUuid);
        if (spkRow == null) {
            throw new IllegalStateException("no SPK for " + accountUuid);
        }

        // Load the KEM pre-key that the initiator chose.
        final DatabaseBackend.X3dhpqKemPreKeyRow kemRow =
                db.loadX3dhpqKemPreKey(accountUuid, env.kemKeyId);
        if (kemRow == null) {
            throw new IllegalStateException("KEM pre-key " + env.kemKeyId + " not found");
        }

        // Load the OPK if one was used.
        byte[] opkPriv = null;
        if (env.opkId != 0) {
            final DatabaseBackend.X3dhpqOneTimePreKeyRow opkRow =
                    db.loadX3dhpqOneTimePreKey(accountUuid, env.opkId);
            if (opkRow != null) {
                opkPriv = opkRow.privX25519();
                // Mark consumed so it is not re-published.
                db.markX3dhpqOneTimePreKeyConsumed(accountUuid, env.opkId);
            }
        }

        // Derive peerDikX25519Pub from the initiator's DC carried in the envelope.
        byte[] peerDikX25519Pub;
        if (env.dcMarshal != null && env.dcMarshal.length > 0) {
            peerDikX25519Pub = DeviceCertificate.unmarshal(env.dcMarshal).getDikPubX25519();
        } else {
            // Fallback: envelope should always carry DC; this path is for D4 unit tests.
            peerDikX25519Pub = env.aikEd25519Pub;
        }

        // Run responder.
        final PqxdhResult result = PqxdhResponder.respond(
                spkRow.privX25519(),
                dik.getPrivX25519(),
                dik.getPubX25519(),
                kemRow.privateKey(),
                opkPriv,
                peerDikX25519Pub,
                env.ephemeralPub,
                env.kemCiphertext,
                X3dhpqCrypto.HKDF_SHA512);

        // Persist session state. The responder's "send DH" private must be
        // its SPK private (NOT a fresh ephemeral) — the initiator pre-
        // ratchets `dh_ratchet_step(rk, eph_priv, peer_SPK_pub, zeros)`,
        // and we need the symmetric ECDH match on first decrypt.
        final long now = System.currentTimeMillis() / 1000L;
        db.putX3dhpqSession(accountUuid, peer, peerDeviceId,
                serialiseResponderSession(result, spkRow.privX25519(), spkRow.pubX25519()), now);

        return result;
    }

    // Serialise a PqxdhResult into a Session blob.
    // Generates an ephemeral DH keypair for use as the session's initial sending DH.
    static byte[] serialiseSession(final PqxdhResult r) {
        final im.conversations.x3dhpq.crypto.KeyPair ephDh = X3dhpqCrypto.x25519GenerateKeypair();
        final Session session = Session.fromPqxdh(r, ephDh.priv, ephDh.pub);
        return session.marshal();
    }

    // Initiator session that pre-ratchets against peerSpkPub, matching the
    // responder side's first-decrypt DH ratchet. Required for interop with
    // dino-fork (and the Go reference): the responder derives its
    // chainRecvKey from dh_ratchet_step(rk, peer_SPK_priv, our_eph_pub),
    // so the initiator must seed chainSendKey from the symmetric ECDH on
    // its side rather than leaving it as raw rootKey[32:64].
    static byte[] serialiseInitiatorSession(final PqxdhResult r, byte[] peerSpkPub) {
        final Session session = Session.fromPqxdhSenderWithPeerDh(r, peerSpkPub);
        return session.marshal();
    }

    // Responder session whose initial sending DH is our SPK keypair (NOT a
    // fresh ephemeral). The initiator pre-ratcheted against peer_SPK_pub,
    // so when the initiator's first message arrives we run the symmetric
    // first-decrypt DH ratchet using SPK_priv to derive the same chain.
    static byte[] serialiseResponderSession(
            final PqxdhResult r, byte[] mySpkPriv, byte[] mySpkPub) {
        final Session session = Session.fromPqxdhReceiverWithDh(r, mySpkPriv, mySpkPub);
        return session.marshal();
    }

    // Parse UTF-8 XML bytes back into a Bundle extension; throws on failure.
    private static Bundle parseBundleXml(final byte[] xmlBytes) throws Exception {
        // Use the Conversations XmlReader which wraps Android XmlPullParser.
        final eu.siacs.conversations.xml.XmlReader reader =
                new eu.siacs.conversations.xml.XmlReader();
        reader.setInputStream(new java.io.ByteArrayInputStream(xmlBytes));
        // Read the first tag (should be the <bundle> start tag).
        eu.siacs.conversations.xml.Tag tag = reader.readTag();
        if (!(tag instanceof eu.siacs.conversations.xml.Tag.Start start)) {
            throw new Exception("expected start tag, got " + tag.getClass().getSimpleName());
        }
        eu.siacs.conversations.xml.Element element = reader.readElement(start);
        if (element instanceof Bundle) return (Bundle) element;
        // If wrapped in an outer element, search children.
        eu.siacs.conversations.xml.Element child = element.findChild("bundle");
        if (child instanceof Bundle) return (Bundle) child;
        throw new Exception("no Bundle element found in parsed XML");
    }

    // Serialise a Bundle extension to its UTF-8 XML bytes; falls back to empty array on error.
    private static byte[] serialiseBundleToXml(final Bundle bundle) {
        try {
            return StreamElementWriter.asStringUnchecked(bundle).getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.w(Config.LOGTAG, "x3dhpq: bundle serialisation failed, storing empty blob: " + e.getMessage());
            return new byte[0];
        }
    }

    // Navigate iq → pubsub → items → item(0) → child of type clazz; returns null on any miss.
    private static <T extends Extension> T extractPubsubPayload(final Iq iq, final Class<T> clazz) {
        final PubSub pubsub = iq.getExtension(PubSub.class);
        if (pubsub == null) return null;
        final im.conversations.android.xmpp.model.pubsub.Items items = pubsub.getItems();
        if (items == null) return null;
        return items.getFirstItem(clazz);
    }

    // Domain separator for the devicelist SignedPart (layout A): 20 ASCII + 0x00.
    private static final byte[] DEVICELIST_SIGNED_PREFIX = {
        'X', '3', 'D', 'H', 'P', 'Q', '-', 'D', 'e', 'v', 'i', 'c', 'e',
        'L', 'i', 's', 't', '-', 'v', '1', 0x00
    };
    // SignedPart header preceding the per-device records: prefix(21) + version(8)
    // + issued_at(8). Layout A has NO num_devices and NO version_marker — each
    // device is self-delimiting via its cert_len — so this dedicated builder is
    // used instead of the core DeviceList.signedPart() (which prepends a uint16
    // num_devices field and would NOT cross-verify with the Dino fork).
    private static final int DEVICELIST_SIGNED_HEADER_LEN = 21 + 8 + 8;

    /** The canonical devicelist SignedPart (layout A) over devices sorted by id asc. */
    private static byte[] deviceListSignedPart(
            final long version,
            final long issuedAt,
            final List<im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> entries) {
        final byte[][] certs = new byte[entries.size()][];
        int size = DEVICELIST_SIGNED_HEADER_LEN;
        for (int i = 0; i < entries.size(); i++) {
            // Prefer the verbatim wire cert bytes when present (verify path, §8.4) so
            // the SignedPart is reconstructed over the issuer's exact bytes; fall back
            // to a fresh marshal for locally built entries (publish path).
            final byte[] raw = entries.get(i).getRawCert();
            certs[i] = raw != null ? raw : entries.get(i).getCert().marshal();
            size += 4 + 8 + 1 + 4 + certs[i].length;
        }
        final ByteBuffer buf = ByteBuffer.allocate(size).order(java.nio.ByteOrder.BIG_ENDIAN);
        buf.put(DEVICELIST_SIGNED_PREFIX);
        buf.putLong(version);
        buf.putLong(issuedAt);
        for (int i = 0; i < entries.size(); i++) {
            final im.conversations.x3dhpq.types.DeviceList.DeviceListEntry e = entries.get(i);
            buf.putInt((int) (e.getDeviceId() & 0xffffffffL));
            buf.putLong(e.getAddedAt());
            buf.put(e.getFlags());
            buf.putInt(certs[i].length);
            buf.put(certs[i]);
        }
        return buf.array();
    }

    /** Hash of the device-records portion of the SignedPart (excludes version + issued_at). */
    private static byte[] deviceListContentHash(
            final List<im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> entries) {
        final byte[] sp = deviceListSignedPart(0L, 0L, entries);
        final byte[] records =
                Arrays.copyOfRange(sp, DEVICELIST_SIGNED_HEADER_LEN, sp.length);
        return X3dhpqCrypto.SHA256.hash(records);
    }

    /**
     * (Re)publishes the account's single authoritative devicelist. Builds the
     * signed-input entries from the UNION of two sources: devices whose private
     * key lives on THIS install ({@code x3dhpq_local_device}) and co-account
     * devices this side has certified but does not hold the key for — e.g. a
     * device enrolled via pairing while acting as the existing/primary side, or
     * any device that has self-healed its co-account set from the account's own
     * inbound devicelist (see {@link #handleInboundDeviceList}, §8.2)
     * ({@code x3dhpq_co_account_device}). Publishing from local rows alone would
     * let each physical device overwrite the account's {@code current} item with
     * only itself, silently dropping messages to every other device (§8.2).
     * Public so callers outside this class (e.g. the pairing UI, on enrolling a
     * new device) can trigger a republish once the union changes.
     */
    public void publishDeviceList() {
        publishDeviceList(java.util.Collections.emptySet());
    }

    /**
     * Overload of {@link #publishDeviceList()} that additionally names the device
     * ids being explicitly revoked in this call (§8.6). Every other caller should
     * keep using the no-arg overload, which passes an empty set.
     *
     * <p>Before signing/sending, this enforces the "no accidental/injected
     * devicelist shrink without revocation" guard: a device set SMALLER than the
     * account's last committed authoritative set (see {@code
     * DatabaseBackend#putX3dhpqCommittedDevices}) — other than the ids in {@code
     * allowRemovals} — is refused outright, so a transient/buggy/injected partial
     * local state can never silently drop a contact's devices.
     */
    public void publishDeviceList(final java.util.Set<Integer> allowRemovals) {
        final String accountUuid = account.getUuid();
        final String ownerJid = account.getJid().asBareJid().toString();

        // Build the canonical core entries from the union, keyed by device_id so a
        // locally-generated row always wins over a cached co-account entry for the
        // same id (should not normally collide), then sorted ascending (unsigned)
        // — the §8.3 signed-input order.
        final java.util.Map<Long, im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> byDeviceId =
                new java.util.LinkedHashMap<>();

        for (final DatabaseBackend.X3dhpqLocalDeviceRow row : db.listX3dhpqLocalDevices(accountUuid)) {
            final DeviceCertificate cert;
            try {
                cert = DeviceCertificate.unmarshal(row.dc());
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": skipping local device " + row.deviceId()
                        + " with unparseable DC: " + e.getMessage());
                continue;
            }
            byDeviceId.put(row.deviceId() & 0xffffffffL,
                    new im.conversations.x3dhpq.types.DeviceList.DeviceListEntry(
                            row.deviceId() & 0xffffffffL, row.createdAt(), (byte) row.flags(), cert));
        }
        for (final DatabaseBackend.X3dhpqCoAccountDeviceRow row : db.listX3dhpqCoAccountDevices(accountUuid)) {
            final long id = row.deviceId() & 0xffffffffL;
            if (byDeviceId.containsKey(id)) {
                continue;
            }
            final DeviceCertificate cert;
            try {
                cert = DeviceCertificate.unmarshal(row.dc());
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": skipping co-account device " + row.deviceId()
                        + " with unparseable DC: " + e.getMessage());
                continue;
            }
            byDeviceId.put(id, new im.conversations.x3dhpq.types.DeviceList.DeviceListEntry(
                    id, row.addedAt(), (byte) row.flags(), cert));
        }

        final List<Long> sortedIds = new ArrayList<>(byDeviceId.keySet());
        sortedIds.sort(java.util.Comparator.naturalOrder());
        final List<im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> entries =
                new ArrayList<>();
        for (final Long id : sortedIds) {
            entries.add(byDeviceId.get(id));
        }

        // Guard: refuse to publish a devicelist that drops a previously-known
        // device without an explicit §8.6 revocation. prevIds is the committed
        // set — independent of x3dhpq_local_device/x3dhpq_co_account_device (the
        // volatile tables just unioned above) — so this cannot be a circular
        // check. First-ever publish (prevIds empty), an identical republish, and
        // a growing list are all unaffected (missing stays empty).
        final java.util.Set<Integer> newIds = new java.util.LinkedHashSet<>();
        for (final Long id : sortedIds) {
            newIds.add((int) (long) id);
        }
        final java.util.Set<Integer> prevIds = db.loadX3dhpqCommittedDeviceIds(accountUuid);
        final java.util.Set<Integer> missing =
                devicesDroppedWithoutRevocation(prevIds, newIds, allowRemovals);
        if (!missing.isEmpty()) {
            final StringBuilder missingIds = new StringBuilder();
            for (final Integer id : missing) {
                if (missingIds.length() > 0) missingIds.append(',');
                missingIds.append(id);
            }
            Log.w(Config.LOGTAG, LOGPREFIX
                    + ": refusing to publish a devicelist that drops known device(s) "
                    + missingIds + " without revocation");
            return;
        }

        // Decide the monotonic version (§8.2): first publish => 1; content change
        // => previous + 1; unchanged republish => reuse. Never hardcoded.
        final byte[] contentHash = deviceListContentHash(entries);
        final DatabaseBackend.X3dhpqDeviceListStateRow state =
                db.loadX3dhpqDeviceListState(accountUuid, ownerJid);
        final long version;
        if (state == null) {
            version = 1L;
        } else if (!Arrays.equals(state.contentHash(), contentHash)) {
            version = state.version() + 1L;
        } else {
            version = state.version();
        }

        final long issuedAt = System.currentTimeMillis() / 1000L;

        // Hybrid-sign the SignedPart over the account's own AIK (§8.2/§7.7).
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": cannot sign devicelist — no AIK row");
            return;
        }
        final AccountIdentityKey aik;
        try {
            aik = AccountIdentityKey.unmarshal(aikRow.aikPriv());
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": cannot load AIK priv to sign devicelist: "
                    + e.getMessage());
            return;
        }
        final byte[] signedPart = deviceListSignedPart(version, issuedAt, entries);
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(aik.getPrivEd25519(), signedPart);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(aik.getPrivMLDSA(), signedPart);

        // Persist our own monotonic state (we always publish signed).
        db.putX3dhpqDeviceListState(accountUuid, ownerJid, version, contentHash, true,
                System.currentTimeMillis() / 1000L);
        // Re-baseline the shrink guard's committed set to what we are publishing now.
        db.putX3dhpqCommittedDevices(accountUuid, newIds);

        final DeviceList list =
                X3dhpqStanzaBuilder.buildDeviceList(db, accountUuid, version, issuedAt);
        // <sig>/<mldsa-sig> are the last children of <devicelist> (§8.4).
        list.setSig(sigEd);
        list.setMldsaSig(sigMl);
        final im.conversations.android.xmpp.model.stanza.Iq iq =
                mXmppConnectionService
                        .getIqGenerator()
                        .generateX3dhpqPublishDeviceList(list, "current");
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    if (response.getType() == Iq.Type.ERROR) {
                        Log.w(
                                Config.LOGTAG,
                                account.getJid().asBareJid()
                                        + ": x3dhpq devicelist publish failed: "
                                        + response);
                    } else {
                        Log.d(
                                Config.LOGTAG,
                                account.getJid().asBareJid()
                                        + ": x3dhpq devicelist published");
                    }
                });
    }

    /**
     * Pure decision logic for the {@link #publishDeviceList(java.util.Set)} shrink
     * guard: the set of device ids present in {@code prevIds} (the last committed
     * authoritative set) that are about to be silently dropped by publishing {@code
     * newIds} — i.e. neither still present in {@code newIds} nor explicitly named in
     * {@code allowRemovals} (§8.6). A non-empty result means the publish must be
     * refused. {@code allowRemovals} may be {@code null}, treated as empty. Package-
     * visible and side-effect free so it can be unit-tested without a live
     * connection service.
     */
    static java.util.Set<Integer> devicesDroppedWithoutRevocation(
            final java.util.Set<Integer> prevIds,
            final java.util.Set<Integer> newIds,
            final java.util.Set<Integer> allowRemovals) {
        final java.util.Set<Integer> missing = new java.util.LinkedHashSet<>(prevIds);
        missing.removeAll(newIds);
        if (allowRemovals != null) {
            missing.removeAll(allowRemovals);
        }
        return missing;
    }

    /**
     * Revokes one of the account's own devices (§8.6). Deletes its local key
     * material, republishes the signed devicelist with the device omitted and the
     * version bumped (the authoritative removal — item ③ machinery), and appends a
     * {@code RemoveDevice} audit entry (§11.4 layout D) to the audit node as
     * corroborating, tamper-evident evidence. Peers and co-account devices tear
     * down state for the vanished device on observing the version-advanced list
     * (handled inbound by {@link #handleInboundDeviceList} + the remote-device prune).
     */
    public void revokeOwnDevice(final int deviceId) {
        if (db == null || account == null || mXmppConnectionService == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": revokeOwnDevice ignored — no db/account/service");
            return;
        }
        final String accountUuid = account.getUuid();
        final String ownerJid = account.getJid().asBareJid().toString();

        // 1. Drop the device so it is omitted from the republished list — from both
        //    the local table (device whose key lives on this install) and the
        //    co-account table (device certified here but keyed elsewhere), since
        //    publishDeviceList() unions both (§8.2).
        db.deleteX3dhpqLocalDevice(accountUuid, deviceId);
        db.deleteX3dhpqCoAccountDevice(accountUuid, deviceId);

        // 2. Republish the signed devicelist, naming deviceId as an explicitly
        //    allowed removal so the shrink guard permits dropping exactly this id.
        //    Because the content changed, the monotonic version strictly increases,
        //    making the removal authoritative for contacts and co-account devices
        //    (§8.6 step 1).
        publishDeviceList(java.util.Set.of(deviceId));

        // 3. Append + publish the RemoveDevice audit entry (§8.6 step 2). Best-effort:
        //    the removal is already authoritative via the signed list above.
        try {
            publishRemoveDeviceAuditEntry(accountUuid, ownerJid, deviceId);
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": RemoveDevice audit entry publish failed for "
                    + deviceId + " (removal still authoritative via signed devicelist): "
                    + e.getMessage());
        }
    }

    /** Builds, persists and publishes a hybrid-signed RemoveDevice audit entry (layout D). */
    private void publishRemoveDeviceAuditEntry(
            final String accountUuid, final String ownerJid, final int deviceId) {
        final DatabaseBackend backend = mXmppConnectionService.databaseBackend;

        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": no AIK — cannot sign RemoveDevice audit entry");
            return;
        }
        final AccountIdentityKey aik = AccountIdentityKey.unmarshal(aikRow.aikPriv());

        // Chain onto our own audit head: seq = last+1, prevHash = SHA-256(last.marshal()).
        final List<DatabaseBackend.X3dhpqAuditEntryRow> chain =
                backend.loadX3dhpqAuditChain(accountUuid, ownerJid);
        final long seq;
        final byte[] prevHash;
        if (chain.isEmpty()) {
            seq = 0L;
            prevHash = new byte[32];
        } else {
            final DatabaseBackend.X3dhpqAuditEntryRow last = chain.get(chain.size() - 1);
            final im.conversations.x3dhpq.types.AuditEntry lastEntry =
                    new im.conversations.x3dhpq.types.AuditEntry(
                            last.seq(), last.prevHash(), last.action(), last.payload(),
                            last.timestamp(), last.sigEd25519(), last.sigMldsa());
            prevHash = X3dhpqCrypto.SHA256.hash(lastEntry.marshal());
            seq = last.seq() + 1L;
        }

        // payload = uint32_BE(device_id) (§11.4 layout D)
        final byte[] payload =
                ByteBuffer.allocate(4).order(java.nio.ByteOrder.BIG_ENDIAN).putInt(deviceId).array();
        final long ts = System.currentTimeMillis() / 1000L;

        final im.conversations.x3dhpq.types.AuditEntry unsigned =
                new im.conversations.x3dhpq.types.AuditEntry(
                        seq, prevHash, im.conversations.x3dhpq.types.AuditEntry.ACTION_REMOVE_DEVICE,
                        payload, ts, new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(aik.getPrivEd25519(), sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(aik.getPrivMLDSA(), sp);
        final im.conversations.x3dhpq.types.AuditEntry signed =
                new im.conversations.x3dhpq.types.AuditEntry(
                        seq, prevHash, im.conversations.x3dhpq.types.AuditEntry.ACTION_REMOVE_DEVICE,
                        payload, ts, sigEd, sigMl);

        backend.putX3dhpqAuditEntry(accountUuid, ownerJid, seq, prevHash,
                im.conversations.x3dhpq.types.AuditEntry.ACTION_REMOVE_DEVICE, payload, ts, sigEd, sigMl);

        final im.conversations.android.xmpp.model.stanza.Iq iq =
                new im.conversations.android.xmpp.model.stanza.Iq(
                        im.conversations.android.xmpp.model.stanza.Iq.Type.SET);
        final PubSub ps = iq.addExtension(new PubSub());
        final im.conversations.android.xmpp.model.pubsub.Publish pub =
                ps.addExtension(new im.conversations.android.xmpp.model.pubsub.Publish());
        pub.setNode(Namespace.X3DHPQ_AUDIT);
        final PubSub.Item item = pub.addExtension(new PubSub.Item());
        item.setId(Long.toString(seq));
        final AuditEntry auditEl = item.addExtension(new AuditEntry());
        auditEl.setContent(signed.marshal());

        Log.d(Config.LOGTAG, LOGPREFIX + ": publishing RemoveDevice audit entry seq=" + seq
                + " for device " + deviceId);
        mXmppConnectionService.sendIqPacket(account, iq, response -> {
            if (response.getType() == im.conversations.android.xmpp.model.stanza.Iq.Type.ERROR) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": RemoveDevice audit publish failed: " + response);
            } else {
                Log.d(Config.LOGTAG, LOGPREFIX + ": RemoveDevice audit entry published (seq=" + seq + ")");
            }
        });
    }

    /**
     * Builds, persists and publishes a hybrid-signed {@code AddDevice} audit entry
     * (§11.4) for a device that was just confirmed via CPace pairing (§10.6.3). Called
     * by the existing/primary side's pairing UI ({@code PairNewDeviceActivity}) right
     * after issuing the device its DC and persisting it into {@code
     * x3dhpq_co_account_device}. This is what makes the sibling pass the {@link
     * #verifiedAddDeviceIds} gate on every device (including this one) that later
     * observes the account's own devicelist.
     */
    public void publishAddDeviceAuditEntry(final int deviceId, final DeviceCertificate issuedCert) {
        if (db == null || account == null || mXmppConnectionService == null || issuedCert == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": publishAddDeviceAuditEntry ignored — missing state");
            return;
        }
        final String accountUuid = account.getUuid();
        final String ownerJid = account.getJid().asBareJid().toString();
        final DatabaseBackend backend = mXmppConnectionService.databaseBackend;

        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": no AIK — cannot sign AddDevice audit entry");
            return;
        }
        final AccountIdentityKey aik = AccountIdentityKey.unmarshal(aikRow.aikPriv());

        final List<DatabaseBackend.X3dhpqAuditEntryRow> chain =
                backend.loadX3dhpqAuditChain(accountUuid, ownerJid);
        final long seq;
        final byte[] prevHash;
        if (chain.isEmpty()) {
            seq = 0L;
            prevHash = new byte[32];
        } else {
            final DatabaseBackend.X3dhpqAuditEntryRow last = chain.get(chain.size() - 1);
            final im.conversations.x3dhpq.types.AuditEntry lastEntry =
                    new im.conversations.x3dhpq.types.AuditEntry(
                            last.seq(), last.prevHash(), last.action(), last.payload(),
                            last.timestamp(), last.sigEd25519(), last.sigMldsa());
            prevHash = X3dhpqCrypto.SHA256.hash(lastEntry.marshal());
            seq = last.seq() + 1L;
        }

        // payload = uint32(device_id) | uint32(cert_len) | DC.Marshal() (§11.4 AddDevice=1)
        final byte[] certBytes = issuedCert.marshal();
        final byte[] payload =
                ByteBuffer.allocate(4 + 4 + certBytes.length)
                        .order(java.nio.ByteOrder.BIG_ENDIAN)
                        .putInt(deviceId)
                        .putInt(certBytes.length)
                        .put(certBytes)
                        .array();
        final long ts = System.currentTimeMillis() / 1000L;

        final im.conversations.x3dhpq.types.AuditEntry unsigned =
                new im.conversations.x3dhpq.types.AuditEntry(
                        seq, prevHash, im.conversations.x3dhpq.types.AuditEntry.ACTION_ADD_DEVICE,
                        payload, ts, new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(aik.getPrivEd25519(), sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(aik.getPrivMLDSA(), sp);
        final im.conversations.x3dhpq.types.AuditEntry signed =
                new im.conversations.x3dhpq.types.AuditEntry(
                        seq, prevHash, im.conversations.x3dhpq.types.AuditEntry.ACTION_ADD_DEVICE,
                        payload, ts, sigEd, sigMl);

        backend.putX3dhpqAuditEntry(accountUuid, ownerJid, seq, prevHash,
                im.conversations.x3dhpq.types.AuditEntry.ACTION_ADD_DEVICE, payload, ts, sigEd, sigMl);

        final im.conversations.android.xmpp.model.stanza.Iq iq =
                new im.conversations.android.xmpp.model.stanza.Iq(
                        im.conversations.android.xmpp.model.stanza.Iq.Type.SET);
        final PubSub ps = iq.addExtension(new PubSub());
        final im.conversations.android.xmpp.model.pubsub.Publish pub =
                ps.addExtension(new im.conversations.android.xmpp.model.pubsub.Publish());
        pub.setNode(Namespace.X3DHPQ_AUDIT);
        final PubSub.Item item = pub.addExtension(new PubSub.Item());
        item.setId(Long.toString(seq));
        final AuditEntry auditEl = item.addExtension(new AuditEntry());
        auditEl.setContent(signed.marshal());

        Log.d(Config.LOGTAG, LOGPREFIX + ": publishing AddDevice audit entry seq=" + seq
                + " for device " + deviceId);
        mXmppConnectionService.sendIqPacket(account, iq, response -> {
            if (response.getType() == im.conversations.android.xmpp.model.stanza.Iq.Type.ERROR) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": AddDevice audit publish failed: " + response);
            } else {
                Log.d(Config.LOGTAG, LOGPREFIX + ": AddDevice audit entry published (seq=" + seq + ")");
            }
        });
    }

    /**
     * Ingests an inbound {@code <audit-entry>} PEP item (§11): persists it (dedup by
     * primary key, see {@code putX3dhpqAuditEntry}'s CONFLICT_IGNORE) and, when it
     * belongs to OUR OWN account's chain, re-verifies the whole locally-stored chain
     * against our current AIK and posts §11.6 UX notifications for newly-seen entries.
     * A verification failure means the chain is broken/tampered — no entries are
     * treated as confirmed in that case (fail closed; see {@link #verifiedAddDeviceIds}).
     */
    private void handleInboundAuditEntry(
            final Jid from,
            final String itemId,
            final im.conversations.android.xmpp.model.x3dhpq.audit.AuditEntry wireEntry) {
        if (db == null || account == null || mXmppConnectionService == null) return;
        final byte[] raw = wireEntry.asBytes();
        if (raw == null || raw.length == 0) return;

        final im.conversations.x3dhpq.types.AuditEntry entry;
        try {
            entry = im.conversations.x3dhpq.types.AuditEntry.unmarshal(raw);
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": malformed inbound audit entry from " + from
                    + ": " + e.getMessage());
            return;
        }

        final String accountUuid = account.getUuid();
        final String ownerJid = from.asBareJid().toString();
        final DatabaseBackend backend = mXmppConnectionService.databaseBackend;
        backend.putX3dhpqAuditEntry(accountUuid, ownerJid, entry.getSeq(), entry.getPrevHash(),
                entry.getAction(), entry.getPayload(), entry.getTimestamp(),
                entry.getSigEd25519(), entry.getSigMLDSA());

        final boolean isOwnChain =
                account.getJid().asBareJid().toString().equals(ownerJid);
        if (!isOwnChain) {
            // Peer audit chains (if ever subscribed to) are out of scope for the
            // self-trust gate; only persisted above for potential future use.
            return;
        }

        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null) {
            // We are still pending-enrollment ourselves — nothing to verify against yet.
            return;
        }
        final AccountIdentityPub ownAik;
        try {
            ownAik = AccountIdentityPub.unmarshal(aikRow.aikPub());
        } catch (final Exception e) {
            return;
        }

        final List<im.conversations.x3dhpq.types.AuditEntry> chain =
                coreAuditChain(backend, accountUuid, ownerJid);
        try {
            final List<im.conversations.x3dhpq.types.AuditEntry> verified =
                    new AccountAuditChainVerifier(mXmppConnectionService, db)
                            .verifyAndStore(accountIdFor(accountUuid), ownAik, chain);
            new AccountAuditChainVerifier(mXmppConnectionService, db)
                    .notifyNewEntries(ownerJid, verified, verified.isEmpty() ? -1 : verified.get(0).getSeq() - 1);
            // A newly-confirmed AddDevice may unblock a sibling the devicelist
            // self-heal previously refused to trust (§10.6.3) — re-run it now that
            // the chain covers it.
            if (entry.getAction() == im.conversations.x3dhpq.types.AuditEntry.ACTION_ADD_DEVICE) {
                requestPeerDeviceList(account.getJid().asBareJid());
            }
        } catch (final AccountAuditChainVerifier.InvalidAuditChainException e) {
            Log.e(Config.LOGTAG, LOGPREFIX + ": OWN audit chain verification FAILED — "
                    + e.getMessage() + " — no sibling device will be trusted via the chain"
                    + " until this is resolved (§10.6.3, fail-closed)");
        }
    }

    /**
     * Returns the set of device ids covered by a valid, chain-verified {@code AddDevice}
     * entry (minus any later validly-chained {@code RemoveDevice}) for {@code ownerJid}'s
     * account audit chain. Fails closed (returns an empty set) if the chain does not
     * verify against our own AIK, or if we have no AIK yet ourselves.
     */
    private java.util.Set<Integer> verifiedAddDeviceIds(final String accountUuid, final String ownerJid) {
        final java.util.Set<Integer> ids = new java.util.HashSet<>();
        if (mXmppConnectionService == null) return ids;
        final DatabaseBackend backend = mXmppConnectionService.databaseBackend;
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow = db.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null) return ids; // pending ourselves — cannot verify, trust nothing
        final AccountIdentityPub ownAik;
        try {
            ownAik = AccountIdentityPub.unmarshal(aikRow.aikPub());
        } catch (final Exception e) {
            return ids;
        }
        final List<im.conversations.x3dhpq.types.AuditEntry> chain =
                coreAuditChain(backend, accountUuid, ownerJid);
        if (chain.isEmpty()) return ids;
        try {
            final List<im.conversations.x3dhpq.types.AuditEntry> verified =
                    new AccountAuditChainVerifier(mXmppConnectionService, db)
                            .verifyAndStore(accountIdFor(accountUuid), ownAik, chain);
            for (final im.conversations.x3dhpq.types.AuditEntry e : verified) {
                if (e.getAction() == im.conversations.x3dhpq.types.AuditEntry.ACTION_ADD_DEVICE) {
                    final byte[] p = e.getPayload();
                    if (p.length >= 4) {
                        ids.add(ByteBuffer.wrap(p).order(java.nio.ByteOrder.BIG_ENDIAN).getInt());
                    }
                } else if (e.getAction() == im.conversations.x3dhpq.types.AuditEntry.ACTION_REMOVE_DEVICE) {
                    final byte[] p = e.getPayload();
                    if (p.length >= 4) {
                        ids.remove(ByteBuffer.wrap(p).order(java.nio.ByteOrder.BIG_ENDIAN).getInt());
                    }
                }
            }
        } catch (final AccountAuditChainVerifier.InvalidAuditChainException e) {
            Log.e(Config.LOGTAG, LOGPREFIX + ": audit chain for " + ownerJid
                    + " failed verification — fail-closed, trusting no sibling: " + e.getMessage());
        }
        return ids;
    }

    private static List<im.conversations.x3dhpq.types.AuditEntry> coreAuditChain(
            final DatabaseBackend backend, final String accountUuid, final String ownerJid) {
        final List<im.conversations.x3dhpq.types.AuditEntry> chain = new ArrayList<>();
        for (final DatabaseBackend.X3dhpqAuditEntryRow r :
                backend.loadX3dhpqAuditChain(accountUuid, ownerJid)) {
            chain.add(new im.conversations.x3dhpq.types.AuditEntry(
                    r.seq(), r.prevHash(), r.action(), r.payload(), r.timestamp(),
                    r.sigEd25519(), r.sigMldsa()));
        }
        return chain;
    }

    /**
     * The DAO's audit-tail-hash cache ({@code getAuditTailHash}/{@code setAuditTailHash})
     * is keyed by a numeric account id; {@code x3dhpq_audit_tail} (the backing table) does
     * not exist yet (tracked as a lead-coordinated schema addition — see the WS4 final
     * report). Until then this derives a stable per-account id from the UUID string so
     * {@link AccountAuditChainVerifier} has SOME cache key; since the DAO methods are
     * presently stubs (always miss), every call re-verifies the chain from genesis, which
     * is correct, just not cached.
     */
    private static long accountIdFor(final String accountUuid) {
        return accountUuid == null ? 0L : accountUuid.hashCode();
    }

    /** Best-effort local UX ping for an unconfirmed self-device (§10.6.3); no persistence. */
    private void surfaceUnconfirmedSiblingEvent(final int deviceId) {
        if (mXmppConnectionService == null || account == null) return;
        new AccountAuditChainVerifier(mXmppConnectionService, db)
                .notifySecurityEvent(
                        account.getJid().asBareJid().toString(),
                        "An unconfirmed device (id " + Integer.toUnsignedString(deviceId)
                                + ") appeared on your account's devicelist without a valid"
                                + " AddDevice record. It has NOT been trusted. If this was not"
                                + " you, your account devicelist may be compromised.");
    }

    /**
     * §10.6.5 identity-reconstruction re-trust gate: true once an inbound devicelist for
     * {@code peerBareJid} failed AIK-signature verification against our previously
     * pinned AIK for them (i.e. looked like a silent AIK reconstruction, §8.5 fork
     * rejection) and the user has not yet explicitly re-trusted it via {@link
     * #reTrustIdentity}. While true, {@link #isCapable(Conversation)} returns false for
     * conversations with this peer so the caller (WS5's {@code
     * Conversation#computeDefaultEncryption()}) stops offering x3dhpq to them — NOTE:
     * that fork point is NOT owned by WS4 and currently checks the hard pq_upgraded
     * latch BEFORE calling isCapable(), so this alone does not yet fully block sending
     * once the latch is set; see the WS4 final report for the one-line hook still needed
     * there.
     */
    public boolean isIdentityBlocked(final Jid peerBareJid) {
        if (mXmppConnectionService == null || account == null || peerBareJid == null) return false;
        final Conversation c =
                mXmppConnectionService.find(account, peerBareJid.asBareJid());
        return c != null && c.getBooleanAttribute(ATTRIBUTE_X3DHPQ_IDENTITY_BLOCKED, false);
    }

    /** Convenience overload of {@link #isIdentityBlocked(Jid)} for a conversation already in hand. */
    public boolean isIdentityBlocked(final Conversation conversation) {
        return conversation != null
                && conversation.getBooleanAttribute(ATTRIBUTE_X3DHPQ_IDENTITY_BLOCKED, false);
    }

    /**
     * Persists the §10.6.5 "stop sending, needs explicit re-trust" flag for {@code
     * peerBareJid} as a Conversation attribute (no schema change: reuses the existing
     * generic attributes JSON blob, mirroring the WS5 {@code ATTRIBUTE_PQ_UPGRADED}
     * latch). Also clears the stale TOFU pin (cached bundle/devicelist-state rows) for
     * this peer so a subsequent {@link #reTrustIdentity} cleanly re-adopts the new AIK
     * instead of comparing against the old one again.
     */
    private void flagIdentityReconstructionEvent(final Jid peerBareJid) {
        if (mXmppConnectionService == null || account == null) return;
        final Conversation c = mXmppConnectionService.find(account, peerBareJid.asBareJid());
        if (c != null && c.setAttribute(ATTRIBUTE_X3DHPQ_IDENTITY_BLOCKED, true)) {
            mXmppConnectionService.databaseBackend.updateConversation(c);
        }
        new AccountAuditChainVerifier(mXmppConnectionService, db)
                .notifySecurityEvent(
                        peerBareJid.asBareJid().toString(),
                        "This contact's identity key appears to have changed (account"
                                + " reconstructed or wiped). Messages to them are paused until"
                                + " you explicitly re-trust the new identity (§10.6.5).");
    }

    /**
     * §10.6.5: explicit user action to re-trust a contact after an identity
     * reconstruction was detected. Clears the block flag and the stale TOFU pin
     * (cached remote devices/bundles/devicelist-state) for {@code peerBareJid} so the
     * NEXT inbound devicelist/bundle is adopted fresh as a new first-contact pin,
     * exactly as if this were the first time we ever saw this peer. Does not itself
     * fetch anything — callers should follow up with {@link #requestPeerDeviceList}.
     */
    public void reTrustIdentity(final Jid peerBareJid) {
        if (mXmppConnectionService == null || account == null || peerBareJid == null) return;
        final String accountUuid = account.getUuid();
        final String peer = peerBareJid.asBareJid().toString();
        final Conversation c = mXmppConnectionService.find(account, peerBareJid.asBareJid());
        if (c != null && c.setAttribute(ATTRIBUTE_X3DHPQ_IDENTITY_BLOCKED, false)) {
            mXmppConnectionService.databaseBackend.updateConversation(c);
        }
        // Reset TOFU: pruneX3dhpqRemoteDevicesNotIn with an EMPTY keep-set drops every
        // cached x3dhpq_remote_device row for this peer AND cascades into
        // x3dhpq_remote_bundle + x3dhpq_session (see its Javadoc), so the pinned-AIK
        // mismatch guard in handleInboundBundle has nothing stale left to compare
        // against — the next devicelist/bundle fetch pins the NEW AIK fresh, exactly
        // as if this were first contact.
        db.pruneX3dhpqRemoteDevicesNotIn(accountUuid, peer, java.util.Collections.emptySet());
        // Reset the devicelist version/fork-detection state so the reconstructed list
        // (whatever version it is) is accepted as a fresh baseline instead of being
        // compared against the pre-reconstruction version/content hash.
        db.putX3dhpqDeviceListState(accountUuid, peer, -1L, new byte[0], false, 0L);
        Log.i(Config.LOGTAG, LOGPREFIX + ": " + peer
                + " explicitly re-trusted (§10.6.5) — TOFU pin reset, requesting fresh devicelist");
        requestPeerDeviceList(peerBareJid);
    }

    private void publishOwnBundle() {
        // load the (single) local device row to obtain the active deviceId
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows =
                db.listX3dhpqLocalDevices(account.getUuid());
        if (rows.isEmpty()) {
            Log.w(
                    Config.LOGTAG,
                    account.getJid().asBareJid()
                            + ": x3dhpq publishOwnBundle skipped — no local device row");
            return;
        }
        final int deviceId = rows.get(0).deviceId();
        final Bundle bundle =
                X3dhpqStanzaBuilder.buildBundle(db, account.getUuid(), deviceId);
        final im.conversations.android.xmpp.model.stanza.Iq iq =
                mXmppConnectionService
                        .getIqGenerator()
                        .generateX3dhpqPublishBundle(bundle, deviceId);
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    if (response.getType() == Iq.Type.ERROR) {
                        Log.w(
                                Config.LOGTAG,
                                account.getJid().asBareJid()
                                        + ": x3dhpq bundle publish failed: "
                                        + response);
                    } else {
                        Log.d(
                                Config.LOGTAG,
                                account.getJid().asBareJid()
                                        + ": x3dhpq bundle published (deviceId="
                                        + deviceId
                                        + ")");
                    }
                });
    }

    // ---- Pairing rendezvous: <pair-hello> (XEP §10.1a) ----

    /**
     * Method B rendezvous (§10.1a): publishes a {@code <pair-hello>} item to THIS device's own PEP
     * node {@code urn:xmppqr:x3dhpq:pair:0} (item {@code current}, whitelist access) carrying only
     * our own device-id, full JID and the CPace {@code sid}. An existing primary resource on the
     * same account receives it via self-PEP {@code +notify} and initiates the pairing FSM toward us.
     * Carries no secret material; the pairing code travels out-of-band only.
     */
    public void publishPairHello(final byte[] sid) {
        if (db == null || account == null || mXmppConnectionService == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": publishPairHello ignored — no db/account/service");
            return;
        }
        final Integer deviceId = getOwnDeviceIdOrNull();
        if (deviceId == null) {
            Log.w(Config.LOGTAG, getLogprefix() + "publishPairHello skipped — no local device row");
            return;
        }
        final im.conversations.android.xmpp.model.x3dhpq.pair.PairHello hello =
                buildPairHello(deviceId, account.getJid(), sid);

        final Iq iq = new Iq(Iq.Type.SET);
        final PubSub ps = iq.addExtension(new PubSub());
        final im.conversations.android.xmpp.model.pubsub.Publish pub =
                ps.addExtension(new im.conversations.android.xmpp.model.pubsub.Publish());
        pub.setNode(Namespace.X3DHPQ_PAIR);
        final PubSub.Item item = pub.addExtension(new PubSub.Item());
        item.setId("current");
        item.addExtension(hello);
        ps.addExtension(
                im.conversations.android.xmpp.model.pubsub.PublishOptions.of(
                        im.conversations.android.xmpp.NodeConfiguration.WHITELIST));

        Log.d(Config.LOGTAG, getLogprefix() + "publishing pair-hello (method B) for device-id="
                + Integer.toUnsignedString(deviceId));
        mXmppConnectionService.sendIqPacket(account, iq, response -> {
            if (response.getType() == Iq.Type.ERROR) {
                Log.w(Config.LOGTAG, getLogprefix() + "pair-hello publish failed: " + response);
            } else {
                Log.d(Config.LOGTAG, getLogprefix() + "pair-hello published to own PEP");
            }
        });
    }

    /**
     * Method A rendezvous (§10.1a): sends the same {@code <pair-hello>} element as a directed,
     * secret-free {@code <message>} to {@code existingFullJid} (learned from the scanned QR). The
     * existing device handles it identically to the self-PEP path and initiates the pairing FSM
     * back toward us.
     */
    public void sendDirectedPairHello(final Jid existingFullJid, final byte[] sid) {
        if (db == null || account == null || mXmppConnectionService == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": sendDirectedPairHello ignored — no db/account/service");
            return;
        }
        final Integer deviceId = getOwnDeviceIdOrNull();
        if (deviceId == null) {
            Log.w(Config.LOGTAG, getLogprefix() + "sendDirectedPairHello skipped — no local device row");
            return;
        }
        final im.conversations.android.xmpp.model.x3dhpq.pair.PairHello hello =
                buildPairHello(deviceId, account.getJid(), sid);

        final im.conversations.android.xmpp.model.stanza.Message message =
                new im.conversations.android.xmpp.model.stanza.Message(
                        im.conversations.android.xmpp.model.stanza.Message.Type.CHAT);
        message.setTo(existingFullJid);
        message.setFrom(account.getJid());
        message.addExtension(hello);

        Log.d(Config.LOGTAG, getLogprefix() + "sending directed pair-hello (method A) to "
                + existingFullJid);
        mXmppConnectionService.sendMessagePacket(account, message);
    }

    /** Builds a {@code <pair-hello>} carrying our own device-id + full JID + base64url sid. */
    private im.conversations.android.xmpp.model.x3dhpq.pair.PairHello buildPairHello(
            final int deviceId, final Jid fullJid, final byte[] sid) {
        final im.conversations.android.xmpp.model.x3dhpq.pair.PairHello hello =
                new im.conversations.android.xmpp.model.x3dhpq.pair.PairHello();
        hello.setDeviceId(deviceId);
        hello.setFullJid(fullJid.toString());
        hello.setSid(
                com.google.common.io.BaseEncoding.base64Url().omitPadding().encode(sid));
        return hello;
    }

    private String getLogprefix() {
        // account may be null only in the test-only no-arg constructor
        final String jid = account != null ? account.getJid().asBareJid().toString() : "test";
        return LOGPREFIX + " (" + jid + "): ";
    }

    // Parse device id from item id string; returns -1 on failure.
    private static int parseDeviceId(final String itemId) {
        if (itemId == null) {
            return -1;
        }
        try {
            return Integer.parseInt(itemId);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /**
     * Sends a SenderChainAnnouncement to a specific peer device as a pairwise envelope.
     * The announcement bytes are wrapped as {@code <payload type='sender-chain'>}.
     */
    public void sendSenderChainAnnouncement(
            final Jid peerBareJid, final int peerDeviceId, final byte[] annBytes) {
        sendSenderChainAnnouncement(peerBareJid, peerDeviceId, annBytes, "sender-chain");
    }

    // payloadType is "sender-chain" (bare announcement) or "group-sync" (the
    // announcement bundled with the membership journal, see GroupCryptoService).
    public void sendSenderChainAnnouncement(
            final Jid peerBareJid, final int peerDeviceId, final byte[] annBytes,
            final String payloadType) {
        if (db == null || account == null || mXmppConnectionService == null) return;
        final String accountUuid = account.getUuid();

        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) return;
        final int ownDeviceId = localRows.get(0).deviceId();

        // Ensure a session exists; if not, establish one
        final im.conversations.x3dhpq.protocol.Session session;
        final XmppX3dhpqMessage.PrekeyMetadata prekeyMeta;
        boolean isFirst = false;

        final DatabaseBackend.X3dhpqSessionRow sessionRow =
                db.loadX3dhpqSession(accountUuid, peerBareJid.asBareJid().toString(), peerDeviceId);
        if (sessionRow == null || sessionRow.stateBlob() == null) {
            final java.util.Optional<im.conversations.x3dhpq.protocol.PqxdhResult> resultOpt =
                    establishOutboundSession(peerBareJid, peerDeviceId);
            if (!resultOpt.isPresent()) {
                Log.d(Config.LOGTAG, LOGPREFIX + ": sendSenderChainAnnouncement deferred — bundle missing for "
                        + peerBareJid + "/" + peerDeviceId);
                return;
            }
            final im.conversations.x3dhpq.protocol.PqxdhResult result = resultOpt.get();
            final im.conversations.x3dhpq.protocol.PrekeyEnvelope env = result.getEnvelope();
            prekeyMeta = env != null ? new XmppX3dhpqMessage.PrekeyMetadata(
                    env.ephemeralPub, env.opkId, env.kemKeyId, env.kemCiphertext,
                    env.dcMarshal, env.aikEd25519Pub, env.aikMldsaPub) : null;
            final DatabaseBackend.X3dhpqSessionRow fresh =
                    db.loadX3dhpqSession(accountUuid, peerBareJid.asBareJid().toString(), peerDeviceId);
            if (fresh == null) return;
            session = im.conversations.x3dhpq.protocol.Session.unmarshal(fresh.stateBlob());
            isFirst = true;
        } else {
            session = im.conversations.x3dhpq.protocol.Session.unmarshal(sessionRow.stateBlob());
            prekeyMeta = null;
        }

        // Build an XmppX3dhpqMessage carrying the announcement as payload
        final XmppX3dhpqMessage xmsg = XmppX3dhpqMessage.createOutboundWithRawPayload(
                account, account.getJid(), ownDeviceId, annBytes);
        xmsg.setPayloadType(payloadType);
        xmsg.addRecipient(peerBareJid, peerDeviceId, session, isFirst, prekeyMeta);

        final im.conversations.android.xmpp.model.stanza.Message packet =
                mXmppConnectionService.getMessageGenerator()
                        .generateX3dhpqSenderChainMessage(peerBareJid, xmsg);
        if (packet != null) {
            mXmppConnectionService.sendMessagePacket(account, packet);
        }

        db.putX3dhpqSession(accountUuid, peerBareJid.asBareJid().toString(), peerDeviceId,
                session.marshal(), System.currentTimeMillis() / 1000L);
    }

    /**
     * Returns true if the conversation is a MUC with a verified group journal that includes our AIK.
     */
    public boolean isCapableForGroup(final Conversation conversation) {
        if (mXmppConnectionService == null) return false;
        final eu.siacs.conversations.crypto.x3dhpq.GroupCryptoService gcs =
                mXmppConnectionService.getGroupCryptoService(account);
        if (gcs == null) return false;
        return gcs.isCapableForGroup(conversation);
    }

    /**
     * Returns the numeric device id for our own local device, or {@code null} if none is registered.
     *
     * <p>Device ids are uint32 values stored in a signed Java {@code int}. Negative values are therefore
     * valid and must not be treated as "missing".
     */
    public Integer getOwnDeviceIdOrNull() {
        if (db == null || account == null) return null;
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows =
                db.listX3dhpqLocalDevices(account.getUuid());
        return rows.isEmpty() ? null : rows.get(0).deviceId();
    }

    /**
     * Returns the numeric device id for our own local device, or -1 if none is registered.
     *
     * <p>Prefer {@link #getOwnDeviceIdOrNull()} when the caller must distinguish a missing row from a
     * valid negative signed representation of a uint32 device id.
     */
    public int getOwnDeviceId() {
        final Integer id = getOwnDeviceIdOrNull();
        return id == null ? -1 : id;
    }

    /**
     * Public accessor for the device-management UI: the set of device ids covered by a
     * verified §11.4 {@code AddDevice} audit-chain entry for OUR OWN account (fail-closed —
     * empty if the chain does not verify or we have no AIK yet). Wraps the private {@link
     * #verifiedAddDeviceIds} gate that {@link #surfaceUnconfirmedSiblingEvent} already uses
     * to decide trust; exposing it lets {@code X3dhpqSelfDevicesActivity} show the same
     * confirmed-vs-pending status the trust logic actually enforces, rather than a UI-only
     * guess.
     */
    public java.util.Set<Integer> getVerifiedAddDeviceIds() {
        if (account == null) return java.util.Collections.emptySet();
        return verifiedAddDeviceIds(account.getUuid(), account.getJid().asBareJid().toString());
    }

    /**
     * One row of the account's associated-devices list (device-management UI, §10.6.3):
     * the union of this install's own device row and every co-account sibling device,
     * annotated with "this device"/primary/§11.4 trust status. See {@link
     * #listAssociatedDevices()}.
     */
    public static final class AssociatedDevice {
        public final int deviceId;
        /** Parsed certificate, or {@code null} if the stored DC bytes could not be parsed. */
        public final DeviceCertificate cert;
        public final long addedAt;
        public final boolean primary;
        public final boolean thisDevice;
        /**
         * True if this device is the account's primary (the genesis root of trust, which by
         * construction predates the audit chain and so never has its own AddDevice entry) or
         * is covered by a verified §11.4 AddDevice entry. False means §10.6.3 "pending/
         * unconfirmed" — present on the devicelist but NOT trust-gate confirmed.
         */
        public final boolean confirmed;

        AssociatedDevice(
                final int deviceId,
                final DeviceCertificate cert,
                final long addedAt,
                final boolean primary,
                final boolean thisDevice,
                final boolean confirmed) {
            this.deviceId = deviceId;
            this.cert = cert;
            this.addedAt = addedAt;
            this.primary = primary;
            this.thisDevice = thisDevice;
            this.confirmed = confirmed;
        }
    }

    /**
     * Builds the full associated-devices list for this account (device-management UI): the
     * union of this install's own local device row ({@code x3dhpq_local_device}) and every
     * co-account sibling device ({@code x3dhpq_co_account_device}, populated either by this
     * install's own pairing-as-primary or by the inbound-devicelist self-heal), deduplicated
     * by device id, sorted primary-first then by device id. Returns an empty list while
     * {@link #isPendingEnrollment()} is true (no AIK yet — nothing to list; the caller should
     * show the pending-enrollment banner instead).
     */
    public List<AssociatedDevice> listAssociatedDevices() {
        final List<AssociatedDevice> result = new ArrayList<>();
        if (db == null || account == null || isPendingEnrollment()) {
            return result;
        }
        final Integer ownDeviceId = getOwnDeviceIdOrNull();
        final java.util.Set<Integer> verified = getVerifiedAddDeviceIds();
        final java.util.LinkedHashMap<Integer, AssociatedDevice> byId = new java.util.LinkedHashMap<>();

        for (final DatabaseBackend.X3dhpqLocalDeviceRow row :
                db.listX3dhpqLocalDevices(account.getUuid())) {
            DeviceCertificate cert = null;
            try {
                cert = DeviceCertificate.unmarshal(row.dc());
            } catch (final Exception ignored) {
                // Keep the row even if the stored DC can't be parsed; fingerprint/role
                // just won't be shown for it.
            }
            final boolean primary = (row.flags() & DeviceCertificate.FLAG_PRIMARY) != 0;
            final boolean thisDevice = ownDeviceId != null && ownDeviceId == row.deviceId();
            final boolean confirmed = primary || verified.contains(row.deviceId());
            byId.put(
                    row.deviceId(),
                    new AssociatedDevice(
                            row.deviceId(), cert, row.createdAt(), primary, thisDevice, confirmed));
        }
        for (final DatabaseBackend.X3dhpqCoAccountDeviceRow row :
                db.listX3dhpqCoAccountDevices(account.getUuid())) {
            if (byId.containsKey(row.deviceId())) {
                continue; // this install's own local row already covers this device id
            }
            DeviceCertificate cert = null;
            try {
                cert = DeviceCertificate.unmarshal(row.dc());
            } catch (final Exception ignored) {
                // as above
            }
            final boolean primary = (row.flags() & DeviceCertificate.FLAG_PRIMARY) != 0;
            final boolean confirmed = primary || verified.contains(row.deviceId());
            byId.put(
                    row.deviceId(),
                    new AssociatedDevice(row.deviceId(), cert, row.addedAt(), primary, false, confirmed));
        }
        result.addAll(byId.values());
        result.sort((a, b) -> {
            if (a.primary != b.primary) return a.primary ? -1 : 1;
            return Integer.compareUnsigned(a.deviceId, b.deviceId);
        });
        return result;
    }

    /**
     * Returns true if the conversation has a peer with known devices and bundles,
     * so that an outbound x3dhpq message can be prepared.
     * For 1:1 conversations this checks that we have at least one peer device bundle.
     */
    public boolean isCapable(final Conversation conversation) {
        if (db == null || account == null) return false;
        if (conversation.getMode() != Conversation.MODE_SINGLE) return false;
        final String peer = conversation.getAddress().asBareJid().toString();
        final List<DatabaseBackend.X3dhpqRemoteDeviceRow> remoteDevices =
                db.listX3dhpqRemoteDevices(account.getUuid(), peer);
        for (final DatabaseBackend.X3dhpqRemoteDeviceRow rd : remoteDevices) {
            final DatabaseBackend.X3dhpqRemoteBundleRow bundle =
                    db.loadX3dhpqRemoteBundle(account.getUuid(), peer, rd.deviceId());
            if (bundle != null && bundle.bundleXml() != null && bundle.bundleXml().length > 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Build a ready-to-send XmppX3dhpqMessage for the given outbound Message.
     * Establishes sessions for any peer device that does not yet have one.
     * Returns null if any required bundle is not yet available (caller should retry).
     */
    public XmppX3dhpqMessage preparePayloadMessage(final Message message) {
        if (db == null || account == null) {
            Log.w(Config.LOGTAG, "x3dhpq: preparePayloadMessage skipped — db or account is null");
            return null;
        }

        final Conversation conversation = (Conversation) message.getConversation();
        final String peer = conversation.getAddress().asBareJid().toString();
        final Jid peerJid = conversation.getAddress().asBareJid();
        final String accountUuid = account.getUuid();

        Log.d(Config.LOGTAG,
                "x3dhpq: preparePayloadMessage for peer=" + peer
                        + " account=" + account.getJid().asBareJid());

        // collect our own device id for carbon copy encryption
        final int ownDeviceId = getOwnDeviceId();
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: preparePayloadMessage — no local device row;"
                            + " bootstrap has not run yet or the row was wiped");
            return null;
        }
        final DatabaseBackend.X3dhpqLocalDeviceRow localRow = localRows.get(0);

        // collect peer device ids that have a stored bundle
        final List<DatabaseBackend.X3dhpqRemoteDeviceRow> remoteDevices =
                db.listX3dhpqRemoteDevices(accountUuid, peer);
        if (remoteDevices.isEmpty()) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: peer " + peer
                            + " has no known devices yet; requesting devicelist."
                            + " message will be retried when bundle arrives.");
            requestPeerDeviceList(peerJid);
            return null;
        }
        Log.d(Config.LOGTAG,
                "x3dhpq: peer " + peer + " has " + remoteDevices.size() + " known device(s)");

        final byte[] plaintextBytes = message.getBody() != null
                ? message.getBody().getBytes(StandardCharsets.UTF_8) : new byte[0];

        final XmppX3dhpqMessage xmsg = XmppX3dhpqMessage.createOutbound(
                account, account.getJid(), ownDeviceId, plaintextBytes);

        // Encrypt a per-device <key rid=..> block for every peer device.
        boolean bundleMissing = addRecipientDevices(xmsg, accountUuid, peerJid, remoteDevices, -1);

        // Multi-device self-copy: also encrypt to our OWN other devices so the
        // carbon/MAM copy they receive is decryptable. Mirrors the Dino fork's
        // get_recipients, which adds the account's own bare JID to the recipient
        // set. We skip our own current device id (we don't message ourselves).
        final Jid ownBareJid = account.getJid().asBareJid();
        final List<DatabaseBackend.X3dhpqRemoteDeviceRow> ownDevices =
                db.listX3dhpqRemoteDevices(accountUuid, ownBareJid.toString());
        if (ownDevices.isEmpty()) {
            // We don't yet know our own other devices; request our own
            // devicelist so future sends can fan out to them. Not fatal — the
            // message still goes to the peer without a self copy this round.
            Log.d(Config.LOGTAG,
                    "x3dhpq: own devicelist not cached yet; requesting it for self-copy");
            requestPeerDeviceList(ownBareJid);
        } else {
            bundleMissing |= addRecipientDevices(
                    xmsg, accountUuid, ownBareJid, ownDevices, ownDeviceId);
        }

        if (bundleMissing) {
            // at least one bundle was missing; message will be retried when bundle arrives
            Log.d(Config.LOGTAG,
                    "x3dhpq: at least one bundle missing for " + peer
                            + "; deferring send until +notify or fetch completes");
            return null;
        }

        Log.d(Config.LOGTAG,
                "x3dhpq: envelope ready for " + peer + " ("
                        + remoteDevices.size() + " recipient device(s))");
        return xmsg;
    }

    /**
     * Adds an encrypted {@code <key rid=..>} block to {@code xmsg} for every device
     * of {@code targetBareJid}, establishing a pairwise session where none exists yet.
     * Devices whose id equals {@code skipDeviceId} are skipped (used to avoid
     * encrypting to our own current device when fanning out the self copy).
     *
     * @return true if at least one required bundle was missing (a fetch was kicked
     *         off; the caller should defer and retry when the bundle arrives).
     */
    private boolean addRecipientDevices(
            final XmppX3dhpqMessage xmsg,
            final String accountUuid,
            final Jid targetBareJid,
            final List<DatabaseBackend.X3dhpqRemoteDeviceRow> devices,
            final int skipDeviceId) {
        final String target = targetBareJid.asBareJid().toString();
        boolean bundleMissing = false;
        for (final DatabaseBackend.X3dhpqRemoteDeviceRow rd : devices) {
            final int devId = rd.deviceId();
            if (devId == skipDeviceId) {
                continue;
            }
            final DatabaseBackend.X3dhpqSessionRow sessionRow =
                    db.loadX3dhpqSession(accountUuid, target, devId);

            final Session session;
            XmppX3dhpqMessage.PrekeyMetadata prekeyMeta = null;
            boolean isFirst = false;

            if (sessionRow == null || sessionRow.stateBlob() == null) {
                // no session yet: run initiator PQXDH
                Log.d(Config.LOGTAG,
                        "x3dhpq: no session for " + target + "/" + devId
                                + ", attempting PQXDH initiation");
                final Optional<PqxdhResult> resultOpt =
                        establishOutboundSession(targetBareJid, devId);
                if (!resultOpt.isPresent()) {
                    Log.w(Config.LOGTAG,
                            "x3dhpq: bundle missing for " + target + "/" + devId
                                    + "; fetch was kicked off, message will retry on arrival");
                    bundleMissing = true;
                    continue;
                }
                Log.d(Config.LOGTAG,
                        "x3dhpq: PQXDH session established with " + target + "/" + devId);
                final PqxdhResult result = resultOpt.get();
                final PrekeyEnvelope env = result.getEnvelope();
                if (env != null) {
                    prekeyMeta = new XmppX3dhpqMessage.PrekeyMetadata(
                            env.ephemeralPub, env.opkId, env.kemKeyId,
                            env.kemCiphertext, env.dcMarshal,
                            env.aikEd25519Pub, env.aikMldsaPub);
                }
                // load the freshly persisted session blob
                final DatabaseBackend.X3dhpqSessionRow newRow =
                        db.loadX3dhpqSession(accountUuid, target, devId);
                if (newRow == null) {
                    bundleMissing = true;
                    continue;
                }
                session = Session.unmarshal(newRow.stateBlob());
                isFirst = true;
            } else {
                session = Session.unmarshal(sessionRow.stateBlob());
            }

            xmsg.addRecipient(targetBareJid, devId, session, isFirst, prekeyMeta);

            // persist updated session state after encrypt
            db.putX3dhpqSession(accountUuid, target, devId,
                    session.marshal(), System.currentTimeMillis() / 1000L);
        }
        return bundleMissing;
    }

    /**
     * Load an existing session for a peer device; returns null if no session is stored.
     */
    public Session loadSession(final Jid peerBareJid, final int peerDeviceId) {
        if (db == null || account == null) return null;
        final DatabaseBackend.X3dhpqSessionRow row = db.loadX3dhpqSession(
                account.getUuid(), peerBareJid.asBareJid().toString(), peerDeviceId);
        if (row == null || row.stateBlob() == null) return null;
        return Session.unmarshal(row.stateBlob());
    }

    /**
     * Persist a session that was updated by a decrypt operation.
     */
    public void persistSession(final Jid peerBareJid, final int peerDeviceId, final Session session) {
        if (db == null || account == null) return;
        db.putX3dhpqSession(
                account.getUuid(),
                peerBareJid.asBareJid().toString(),
                peerDeviceId,
                session.marshal(),
                System.currentTimeMillis() / 1000L);
    }

    /**
     * Accepts an inbound PQXDH session from a PrekeyEnvelope and returns the resulting Session.
     * Differs from acceptInboundSession in that it does NOT immediately persist; the caller
     * should call persistSession after a successful decrypt.
     */
    public Session acceptInboundSessionAsSession(
            final Jid peerBareJid, final int peerDeviceId, final PrekeyEnvelope env) {
        final String accountUuid = account != null ? account.getUuid() : "test";
        final String peer = peerBareJid.asBareJid().toString();

        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) {
            throw new IllegalStateException("no local device row for " + accountUuid);
        }
        final DeviceIdentityKey dik = DeviceIdentityKey.unmarshal(localRows.get(0).dikPriv());

        final DatabaseBackend.X3dhpqSignedPreKeyRow spkRow =
                db.loadLatestX3dhpqSignedPreKey(accountUuid);
        if (spkRow == null) {
            throw new IllegalStateException("no SPK for " + accountUuid);
        }

        final DatabaseBackend.X3dhpqKemPreKeyRow kemRow =
                db.loadX3dhpqKemPreKey(accountUuid, env.kemKeyId);
        if (kemRow == null) {
            throw new IllegalStateException("KEM pre-key " + env.kemKeyId + " not found");
        }

        byte[] opkPriv = null;
        if (env.opkId != 0) {
            final DatabaseBackend.X3dhpqOneTimePreKeyRow opkRow =
                    db.loadX3dhpqOneTimePreKey(accountUuid, env.opkId);
            if (opkRow != null) {
                opkPriv = opkRow.privX25519();
                // mark consumed so it is not re-published
                db.markX3dhpqOneTimePreKeyConsumed(accountUuid, env.opkId);
            }
        }

        byte[] peerDikX25519Pub;
        if (env.dcMarshal != null && env.dcMarshal.length > 0) {
            peerDikX25519Pub = DeviceCertificate.unmarshal(env.dcMarshal).getDikPubX25519();
        } else {
            // fallback for test paths where DC is omitted
            peerDikX25519Pub = env.aikEd25519Pub;
        }

        final PqxdhResult result = PqxdhResponder.respond(
                spkRow.privX25519(),
                dik.getPrivX25519(),
                dik.getPubX25519(),
                kemRow.privateKey(),
                opkPriv,
                peerDikX25519Pub,
                env.ephemeralPub,
                env.kemCiphertext,
                X3dhpqCrypto.HKDF_SHA512);

        // build Session from responder result; use SPK as initial DH keypair (matches NewReceivingState)
        return Session.fromPqxdhReceiverWithDh(result, spkRow.privX25519(), spkRow.pubX25519());
    }
}
