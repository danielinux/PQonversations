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
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Dc;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Cert;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Device;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.MldsaSig;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Sig;
import im.conversations.android.xmpp.model.x3dhpq.devtracker.DevTracker;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Envelope;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Key;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Payload;
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
import im.conversations.x3dhpq.types.TrustEntry;
import im.conversations.x3dhpq.types.TrustManifest;
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

    // "<bareJid>/<deviceId>" of recipient devices whose published bundle carries a DC that
    // does NOT verify against the current account AIK (a dead/forked device that was never
    // re-paired, e.g. left over after an account reset). Such a device is not a legitimate
    // recipient — encrypting to it is impossible and it must NOT block delivery to everyone
    // else. Populated when a fetched bundle fails DC verification, cleared when a later fetch
    // for the same device verifies (it was re-paired). Fan-out skips these instead of
    // deferring the whole message. Best-effort in-memory hint; the durable fix is revoking
    // the device from the account manifest.
    private final java.util.Set<String> dcInvalidDevices =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    // Registered listeners; last set wins (used for GROUP/RECOVERY dispatch).
    private DeviceListListener deviceListListener;
    private BundleListener bundleListener;
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
                final eu.siacs.conversations.xmpp.manager.VerifyDeviceManager verify =
                        account.getXmppConnection()
                                .getManager(
                                        eu.siacs.conversations.xmpp.manager.VerifyDeviceManager
                                                .class);
                // Defense-in-depth: this runs on the connection thread, so a null
                // manager must never NPE the whole connection. (The manager is now
                // registered in Managers; this guard only covers a future regression.)
                if (verify != null) {
                    verify.handlePairHello(
                            (im.conversations.android.xmpp.model.x3dhpq.pair.PairHello) payload);
                }
            }
            return true;
        } else if (Namespace.X3DHPQ_DEVTRACKER.equals(node)) {
            // §11.8: a live +notify re-seal of our own tracker (device-set change on
            // another of our devices, or our own echoed publish). Best-effort: catches
            // revocation immediately instead of waiting for the next reconnect. Never
            // allowed to throw into the caller — see interpretDeviceTrackerSafely.
            if (payload instanceof DevTracker
                    && account != null
                    && from != null
                    && from.asBareJid().equals(account.getJid().asBareJid())) {
                interpretDeviceTrackerSafely((DevTracker) payload);
            }
            return true;
        } else if (Namespace.X3DHPQ_TRUSTMANIFEST.equals(node)) {
            // Trust Manifest Phase 2 (contract §A/§C): the live trust source. The whole
            // TrustManifest.marshal() blob is the base64 text of <trustmanifest>.
            if (payload
                    instanceof
                    im.conversations.android.xmpp.model.x3dhpq.trustmanifest.TrustManifestItem) {
                final byte[] blob =
                        ((im.conversations.android.xmpp.model.x3dhpq.trustmanifest.TrustManifestItem)
                                        payload)
                                .asBytes();
                handleInboundTrustManifest(from, blob);
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
        } else if (Namespace.X3DHPQ_DEVTRACKER.equals(node)) {
            final var entry = items.getFirstItemWithId(DevTracker.class);
            if (entry != null) {
                handleEvent(from, node, entry.getKey(), entry.getValue());
            }
        } else if (Namespace.X3DHPQ_TRUSTMANIFEST.equals(node)) {
            final var entry =
                    items.getFirstItemWithId(
                            im.conversations.android.xmpp.model.x3dhpq.trustmanifest
                                    .TrustManifestItem.class);
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

        // §11.8: an already-enrolled device checks on every connect whether it can
        // still decrypt the account's sealed tracker — losing that ability is how
        // revocation reaches an offline device. Best-effort/async; never blocks the
        // publish below.
        try {
            checkDeviceTrackerForRevocation();
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": checkDeviceTrackerForRevocation failed"
                    + " (non-fatal, §11.8): " + e.getMessage());
        }

        // §11.8 "Queued enrollment request": explicitly fetch our own pair-hello item
        // on every connect (in addition to live +notify) so a request queued while we
        // were offline is still discovered and surfaced.
        try {
            fetchPairHelloOnConnect();
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": fetchPairHelloOnConnect failed (non-fatal,"
                    + " §11.8/§10.1a): " + e.getMessage());
        }

        // Republish our devicelist and bundle, then reconcile the Trust Manifest — the
        // LIVE trust source. (The retired account-audit chain used to be caught up here;
        // device trust now comes entirely from the manifest fold, so no audit
        // fetch/genesis step remains.)
        publishDeviceList();
        publishOwnBundle();
        // Trust Manifest Phase 2 (§D1/§D3): the primary migrates today's authorized
        // device set into a genesis manifest (idempotent); every device then fetches
        // and adopts the account's own manifest as the LIVE trust source. A device
        // with no manifest yet simply stays on the devicelist fallback.
        maybePublishGenesisManifest();
        // Task #65: reconcile the local manifest with the server (source of truth) —
        // auto-compact a bloated manifest, adopt a newer server version, or (re)publish
        // ours if the server is behind (a lost publish ACK). Then adopt for a newcomer.
        reconcileOwnManifestOnConnect();
        fetchAndAdoptManifest();
    }

    /**
     * §10.6.6 "Account reset (identity override)": the one destructive device-lifecycle
     * operation. Formerly named {@code generateNewIdentity()} (§10.6.4b registration-
     * choice override); reworked to also carry out the two additional §10.6.6 steps that
     * make this a proper account reset rather than just a local re-mint:
     *
     * <ol>
     *   <li>Mint a brand-new AIK (a new ratchet root) via {@link
     *       LocalKeyBootstrap#mintFreshIdentity}. That call's cascading delete of the OLD
     *       {@code x3dhpq_account_identity} row also drops every {@code
     *       x3dhpq_co_account_device}/{@code x3dhpq_committed_device} row FK-linked to it —
     *       i.e. de-associating ALL previously associated devices is already a side effect
     *       of the mint, so the very next {@link #publishDeviceList()} below publishes a
     *       fresh list containing ONLY the new device, per §10.6.6.</li>
     *   <li>Where this device still held the OLD {@code AIK_priv} (captured BEFORE the
     *       mint), append a {@code RotateAIK} entry (action=3, payload = new AIK pub,
     *       §11.4/§11.7) to the OLD device-audit DAG, signed by the OLD AIK — §12.1 step 3 /
     *       §12.4 ("signed by the old AIK, before it is retired"). This is a LOCAL append to
     *       {@code x3dhpq_device_audit} only (that table has no FK to {@code
     *       x3dhpq_account_identity}, so the OLD chain survives the mint above); there is no
     *       dedicated wire node for individual v2 DAG entries yet in this client (§11.7's
     *       sealed device-state tracker, unchanged by this method, is how a fold of THIS
     *       (new) account state reaches other devices going forward). If the old AIK_priv is
     *       not held (e.g. this device was itself disabled), that step is skipped, per
     *       §10.6.6 "where the old AIK_priv is still held".</li>
     * </ol>
     *
     * <p>What this method deliberately does NOT and cannot do — the caller (UI) MUST
     * present these as destructive BEFORE invoking it (§10.6.6): prior messages under the
     * old identity are lost; the account loses membership in every prior group (its old
     * AIK fingerprint is no longer a journal member) and needs re-invitation; and because
     * this is the "same JID, different AIK" event (§10.6.5), every peer must manually
     * re-validate the new identity before traffic resumes. None of that is a local
     * operation this method can perform.
     *
     * <p>Wrapped so a failure can never crash the caller (bind-safety guardrail): only the
     * identity mint itself is unconditional (mirroring the pre-existing behaviour), every
     * other step here is best-effort/logged-only on failure.
     */
    public void performAccountReset() {
        if (db == null || account == null || mXmppConnectionService == null) return;
        final String accountUuid = account.getUuid();

        // Capture the OLD AIK (if we still hold its private key) and the OLD device-audit
        // DAG's current heads/author-device-id BEFORE mintFreshIdentity() wipes the local
        // identity — both are needed to sign+chain the RotateAIK entry below.
        AccountIdentityKey oldAik = null;
        long oldAuthorDeviceId = 0L;
        im.conversations.x3dhpq.types.DeviceDag oldDag = new im.conversations.x3dhpq.types.DeviceDag();
        try {
            final DatabaseBackend.X3dhpqAccountIdentityRow oldRow =
                    db.loadX3dhpqAccountIdentity(accountUuid);
            if (oldRow != null && oldRow.aikPriv() != null && oldRow.aikPriv().length > 0) {
                oldAik = AccountIdentityKey.unmarshal(oldRow.aikPriv());
            }
            final List<DatabaseBackend.X3dhpqLocalDeviceRow> oldLocalRows =
                    db.listX3dhpqLocalDevices(accountUuid);
            if (!oldLocalRows.isEmpty()) {
                oldAuthorDeviceId = oldLocalRows.get(0).deviceId() & 0xffffffffL;
            }
            for (final DatabaseBackend.X3dhpqDeviceAuditEntryRow row :
                    db.listX3dhpqDeviceAuditEntries(accountUuid)) {
                oldDag.ingest(row.entryBlob());
            }
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": account reset — failed to capture the OLD"
                    + " AIK/DAG state (RotateAIK chain entry will be skipped, non-fatal): "
                    + e.getMessage());
            oldAik = null;
        }

        final LocalKeyBootstrap bootstrap = new LocalKeyBootstrap(mXmppConnectionService.databaseBackend);
        final LocalKeyBootstrap.BootstrapResult result = bootstrap.mintFreshIdentity(accountUuid);
        Log.i(Config.LOGTAG, LOGPREFIX + ": " + account.getJid().asBareJid()
                + " performed an ACCOUNT RESET (§10.6.6) — minted a NEW identity, fp="
                + result.fingerprint + "; every previously associated device is now"
                + " de-associated and the account needs re-invitation to every prior group");

        if (oldAik != null) {
            try {
                appendRotateAikToOldChain(
                        accountUuid, oldAik, oldAuthorDeviceId,
                        oldDag.currentHeads(), oldDag.nextLamport(), result.fingerprint);
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": account reset — RotateAIK chain entry"
                        + " append failed (non-fatal; the new identity is still valid): "
                        + e.getMessage());
            }
        } else {
            Log.i(Config.LOGTAG, LOGPREFIX + ": account reset — no OLD AIK_priv was held by"
                    + " this device; skipping the RotateAIK chain entry (§10.6.6: \"where the"
                    + " old AIK_priv is still held\")");
        }

        // Trust Manifest model (task #55, RESET-ONLY / STRICT): mintFreshIdentity above
        // deleted x3dhpq_account_identity, which cascades (ON DELETE CASCADE) to this
        // account's manifest-state, devicelist-state, co-account and committed-device
        // rows — so the manifest/devicelist state stores are already reset to a clean
        // slate under the NEW AIK. Clear any remaining OWN-account trust cache
        // (x3dhpq_remote_device rows keyed on our own bare JID) that is NOT FK-linked to
        // the identity row, so no device from the OLD (dropped) lineage survives.
        try {
            final String ownBare = account.getJid().asBareJid().toString();
            db.pruneX3dhpqRemoteDevicesNotIn(accountUuid, ownBare, java.util.Collections.emptySet());
            db.deleteX3dhpqManifestState(accountUuid, ownBare);
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": account reset — own-account trust cache purge"
                    + " failed (non-fatal): " + e.getMessage());
        }

        if (!result.pendingEnrollment) {
            // Root a FRESH genesis Trust Manifest: SELF-ONLY (the union after the mint is
            // just this device), version=1 (devicelist-state was cascaded away), prev_hash
            // = 32 zero bytes, genesis entry AIK-signed under the NEW AIK, head signed under
            // this device's DIK. This becomes the live trust source under the new lineage.
            maybePublishGenesisManifest();
            // Republish the derived caches from genesis under the new AIK (§1338 node
            // purge): devicelist:0 (self-only, new-AIK-signed) — this also re-seals and
            // republishes the devtracker:0 node — and the bundle:0 item.
            publishDeviceList();
            publishOwnBundle();
        }
    }

    /**
     * Task #58 recovery: "Join an existing identity". A device that holds its OWN account
     * AIK (thinks it is primary — including one that wrongly self-promoted after a fork) has
     * no way, once it is no longer pending, to discard that identity and re-join the
     * account's existing manifest. This discards THIS device's account-root identity while
     * KEEPING its device key (DIK + device_id), marks it pending, clears the derived trust
     * caches for the discarded identity, and re-runs pending-enrollment resolution:
     * <ul>
     *   <li>if the account already has an identity (another primary) → this device stays
     *       pending and the UI offers "Associate with existing identity" (pair as secondary);</li>
     *   <li>if no other identity is found → {@code resolvePendingEnrollment()} self-corrects
     *       by re-promoting this device to primary (reusing its existing AIK row).</li>
     * </ul>
     * The device publishes NOTHING as primary during this (the pending gate in {@link
     * #publishLocalState()} short-circuits before any primary publish).
     */
    public void discardIdentityAndRejoin() {
        if (db == null || account == null || mXmppConnectionService == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": discardIdentityAndRejoin ignored — no db/account/service");
            return;
        }
        if (isPendingEnrollment()) {
            Log.d(Config.LOGTAG, LOGPREFIX + ": discardIdentityAndRejoin — already pending; re-running"
                    + " enrollment resolution only");
            publishLocalState();
            return;
        }
        final String accountUuid = account.getUuid();
        final String ownBare = account.getJid().asBareJid().toString();

        // 1. Demote to pending: keep DIK + device_id, drop the "primary" status. (The
        //    account_identity row is intentionally kept — x3dhpq_local_device cascades from
        //    it — and is overwritten when this device pairs as a secondary or self-corrects.)
        new LocalKeyBootstrap(mXmppConnectionService.databaseBackend).demoteToPending(accountUuid);

        // 2. Clear every derived trust cache tied to the discarded identity so nothing from
        //    it survives the rejoin: manifest state, devicelist version/fork state, the
        //    co-account + committed device sets, and our own remote-device cache.
        try {
            db.deleteX3dhpqManifestState(accountUuid, ownBare);
            db.putX3dhpqDeviceListState(accountUuid, ownBare, -1L, new byte[0], false, 0L);
            db.pruneX3dhpqCoAccountDevicesNotIn(accountUuid, java.util.Collections.emptySet());
            db.putX3dhpqCommittedDevices(accountUuid, java.util.Collections.emptySet());
            db.pruneX3dhpqRemoteDevicesNotIn(accountUuid, ownBare, java.util.Collections.emptySet());
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": discardIdentityAndRejoin — trust-cache clear failed"
                    + " (non-fatal): " + e.getMessage());
        }

        Log.i(Config.LOGTAG, LOGPREFIX + ": " + ownBare + " discarded its local account identity"
                + " (task #58) — now PENDING; re-detecting the account's existing identity");

        // 3. Re-run pending-enrollment resolution. publishLocalState() sees isPendingEnrollment()
        //    == true and routes to resolvePendingEnrollment() — it publishes NOTHING as primary.
        publishLocalState();
    }

    /**
     * §12.1 step 3 / §12.4: builds, signs with the OLD AIK, and locally appends a {@code
     * RotateAIK} (action=3) device-audit-DAG entry (§11.7) to the OLD chain for {@code
     * accountUuid} — payload {@code uint16(new_aik_len) | AccountIdentityPub.marshal()}
     * per §11.4, chained onto {@code parents} (the OLD DAG's heads captured by the caller
     * before the mint). Mirrors {@link #ensureDeviceAuditGenesis}'s use of the same local-
     * only {@code x3dhpq_device_audit} table — there is no dedicated publish node for
     * individual v2 DAG entries in this client yet.
     */
    private void appendRotateAikToOldChain(
            final String accountUuid,
            final AccountIdentityKey oldAik,
            final long authorDeviceId,
            final List<byte[]> parents,
            final long lamport,
            final String newFingerprintForLog) {
        final DatabaseBackend.X3dhpqAccountIdentityRow newRow = db.loadX3dhpqAccountIdentity(accountUuid);
        if (newRow == null || newRow.aikPub() == null || newRow.aikPub().length == 0) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": account reset — no NEW AIK row available to"
                    + " build the RotateAIK payload from; skipping");
            return;
        }
        final byte[] payload =
                im.conversations.x3dhpq.types.DeviceAuditEntryV2.buildRotateAikPayload(newRow.aikPub());
        final long ts = System.currentTimeMillis() / 1000L;
        final im.conversations.x3dhpq.types.DeviceAuditEntryV2 entry =
                im.conversations.x3dhpq.types.DeviceAuditEntryV2.signNew(
                        oldAik, lamport, authorDeviceId, parents,
                        im.conversations.x3dhpq.types.DeviceAuditEntryV2.ACTION_ROTATE_AIK,
                        payload, ts);
        final String hashHex =
                im.conversations.x3dhpq.types.DeviceAuditEntryV2.hex(entry.computeHash());
        db.putX3dhpqDeviceAuditEntry(accountUuid, hashHex, entry.marshal(), ts);
        Log.i(Config.LOGTAG, LOGPREFIX + ": account reset — appended a RotateAIK entry to the"
                + " OLD device-audit DAG (signed by the OLD AIK, §12.4); new AIK fp="
                + newFingerprintForLog);
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
     * §10.6.6 "authorized vs disabled": true once this device holds {@code AIK_priv} and is
     * a confirmed member of the account's device set — the complement of {@link
     * #isPendingEnrollment()}. This is the single gate for both outbound send (§10.6.6
     * "a disabled device ... MUST NOT send as the account") and device-management actions
     * (§10.6.6 "any authorized device ... may append: authorize a new device ... or revoke
     * any device") — a disabled/pending device must not be able to do either. Returns
     * {@code false} (never authorized) when this service has no live account (test-only
     * construction paths).
     */
    public boolean isAuthorizedDevice() {
        return account != null && !isPendingEnrollment();
    }

    /**
     * Resolves a §10.6.1 pending-enrollment device. §11.8 ENHANCEMENT: first checks
     * whether the account's sealed device-state tracker is published at all — presence
     * alone (a pending device has no AIK yet to verify the signature against) is already
     * the "an account identity already exists" signal, exactly like the pre-existing
     * devicelist-emptiness check below, which is now used only as the fallback when no
     * tracker has been published yet (e.g. a legacy account that predates §11.8, or the
     * very first device — see {@link #resolvePendingEnrollmentViaDeviceList}).
     */
    private void resolvePendingEnrollment() {
        if (db == null || account == null || mXmppConnectionService == null) return;
        fetchDeviceTrackerPresence(present -> {
            if (!isPendingEnrollment()) {
                Log.d(Config.LOGTAG, LOGPREFIX
                        + ": pending-enrollment resolved concurrently (pairing"
                        + " confirmation arrived first); nothing to do");
                return;
            }
            if (present) {
                Log.i(Config.LOGTAG, LOGPREFIX
                        + ": account " + account.getJid().asBareJid()
                        + " already has a published sealed device-state tracker —"
                        + " remaining pending-enrollment, awaiting confirmation by an"
                        + " existing device (§10.6, §11.8)");
                // Stays pending. No publish. UX: X3dhpqSelfDevicesActivity surfaces this
                // state and offers "generate a new identity instead" (§10.6.4b) or
                // Associate (§10.6.4a, now also queues a persistent enrollment request,
                // §11.8 "Queued enrollment request").
                return;
            }
            // Tracker absent: fall back to the pre-§11.8 devicelist-emptiness check
            // (also covers legacy accounts that never published a tracker).
            resolvePendingEnrollmentViaDeviceList();
        });
    }

    /** Pre-§11.8 fallback path of {@link #resolvePendingEnrollment()}; see its docs. */
    private void resolvePendingEnrollmentViaDeviceList() {
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

        // Trust Manifest Phase 2 (contract §C fallback rule): when we already hold an
        // accepted manifest for this owner, the MANIFEST is the live trust source — its
        // fold populated the trust tables. Do not let the (now derived-cache) devicelist
        // re-attest/prune those rows, which would drop DIK-issued sibling DCs the manifest
        // authorized. The devicelist path only applies to owners with NO manifest yet.
        if (db.loadX3dhpqManifestState(accountUuid, peer) != null) {
            Log.d(Config.LOGTAG, LOGPREFIX + ": ignoring devicelist from " + peer
                    + " — a trustmanifest is the live trust source for this owner");
            return;
        }

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
        // §10.6.3 (trust-manifest model): trust = AIK-ATTESTED MEMBERSHIP. A sibling
        // in our own devicelist is trusted iff its embedded DC verifies (both hybrid
        // sigs) under the CURRENT account AIK — not a genesis-rooted audit chain, no
        // fail-closed on a missing genesis. Load the account AIK pub once for the walk.
        AccountIdentityPub ownAikPub = null;
        if (isOwnList) {
            final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                    db.loadX3dhpqAccountIdentity(accountUuid);
            if (aikRow != null && aikRow.aikPub() != null && aikRow.aikPub().length > 0) {
                try {
                    ownAikPub = AccountIdentityPub.unmarshal(aikRow.aikPub());
                } catch (final Exception ignore) {
                    ownAikPub = null;
                }
            }
        }

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
                final DeviceCertificate dc = DeviceCertificate.unmarshal(dcBytes);
                db.putX3dhpqRemoteDevice(accountUuid, peer, id, dcBytes, now);
                liveIds.add(id);
                Log.d(Config.LOGTAG,
                        "x3dhpq: stored remote_device for " + peer + "/" + id);

                if (isOwnList && !localIds.contains(id)) {
                    // trust = the sibling's DC verifies under the CURRENT account AIK
                    // (AIK-attested membership). No genesis-rooted audit chain.
                    boolean attested = false;
                    if (ownAikPub != null) {
                        try {
                            attested = X3dhpqCrypto.ed25519Verify(
                                            ownAikPub.getPubEd25519(), dc.signedPart(), dc.getSigEd25519())
                                    && X3dhpqCrypto.mldsa65Verify(
                                            ownAikPub.getPubMLDSA(), dc.signedPart(), dc.getSigMLDSA());
                        } catch (final Exception verr) {
                            attested = false;
                        }
                    }
                    if (attested) {
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
                                        + " (AIK-attested member)");
                    } else {
                        // DC not attested by the current AIK → not a member. Drop it
                        // (phantom/old-AIK); leaving it out of coAccountLiveIds prunes it.
                        Log.w(Config.LOGTAG,
                                "x3dhpq: dropping sibling device " + id + " from own devicelist"
                                        + " — DC not attested by the current AIK (not a member)");
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
                if (isOwnList) {
                    // trust-manifest model: a phantom/old-AIK DC in our OWN list is
                    // simply not a member — skip that one device rather than reject
                    // the whole list (one-bad-entry tolerance).
                    Log.w(Config.LOGTAG, "x3dhpq: own devicelist has a DC not attested by the"
                            + " current AIK; skipping that device (not rejecting the list)");
                    continue;
                }
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

    // =====================================================================
    // Trust Manifest Phase 2 (contract §A–§F): the manifest is the LIVE trust
    // source. The devicelist publish path (publishDeviceList) is kept as a
    // derived cache = fold output so bundles/groups/UI keep working (§F).
    // =====================================================================

    /** Sends a fetch IQ for the owner's trustmanifest; response feeds handleInboundTrustManifest. */
    public void requestTrustManifest(final Jid ownerBareJid) {
        if (mXmppConnectionService == null) return;
        final Iq iq =
                mXmppConnectionService
                        .getIqGenerator()
                        .generateX3dhpqRequestTrustManifest(ownerBareJid.asBareJid());
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    if (response.getType() != Iq.Type.RESULT) {
                        Log.d(Config.LOGTAG, LOGPREFIX
                                + ": no trustmanifest for " + ownerBareJid
                                + " (type=" + response.getType() + "); devicelist fallback applies");
                        return;
                    }
                    final Extension payload =
                            extractPubsubPayload(
                                    response,
                                    im.conversations.android.xmpp.model.x3dhpq.trustmanifest
                                            .TrustManifestItem.class);
                    if (payload
                            instanceof
                            im.conversations.android.xmpp.model.x3dhpq.trustmanifest
                                    .TrustManifestItem) {
                        final byte[] blob =
                                ((im.conversations.android.xmpp.model.x3dhpq.trustmanifest
                                                .TrustManifestItem)
                                                payload)
                                        .asBytes();
                        handleInboundTrustManifest(ownerBareJid, blob);
                    }
                });
    }

    // ---- Publish robustness (task #65, mirrors Dino publish_manifest_with_retry) --------
    // The manifest is a large PEP item and the server is the AUTHORITATIVE shared copy, so
    // we publish with a per-attempt TIMEOUT and RETRY until confirmed. SINGLE-FLIGHT +
    // LATEST-ONLY: only one publish loop ever runs and it always targets the newest version;
    // a newer edit/compaction/reconcile SUPERSEDES an in-flight attempt (updating the shared
    // slot) instead of spawning a second competing loop. If a round fails after all retries
    // we drop it and let the next connect's reconcile retry — we never accumulate loops.
    private final Object manifestPublishLock = new Object();
    private TrustManifest pendingPublishManifest;      // shared latest-only slot
    private boolean manifestPublishLoopRunning;
    private java.util.concurrent.ScheduledExecutorService manifestPublishExecutor;
    // Backoff before attempt i (attempt 0 fires immediately); giving up once i reaches len.
    private static final long[] MANIFEST_PUBLISH_DELAYS_MS = {0L, 5000L, 10000L, 20000L, 40000L};
    private static final long MANIFEST_PUBLISH_TIMEOUT_MS = 45000L;

    private synchronized java.util.concurrent.ScheduledExecutorService manifestPublishExecutor() {
        if (manifestPublishExecutor == null) {
            manifestPublishExecutor = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
                    r -> {
                        final Thread t = new Thread(r, "X3dhpqManifestPublish");
                        t.setDaemon(true);
                        return t;
                    });
        }
        return manifestPublishExecutor;
    }

    /**
     * Publishes a signed {@link TrustManifest} to the trustmanifest:0 node (contract §A): the
     * whole {@code marshal()} blob is the base64 text of the single {@code <trustmanifest>}
     * element. The caller must have already called {@code signHead(...)}. Single-flight +
     * latest-only + retry-until-confirmed (task #65); returns immediately.
     */
    public void publishTrustManifest(final TrustManifest manifest) {
        if (mXmppConnectionService == null || manifest == null) return;
        synchronized (manifestPublishLock) {
            if (pendingPublishManifest == null
                    || Long.compareUnsigned(manifest.getVersion(), pendingPublishManifest.getVersion()) > 0) {
                pendingPublishManifest = manifest;
            }
            if (manifestPublishLoopRunning) return; // the running loop picks up the newest
            manifestPublishLoopRunning = true;
        }
        manifestPublishExecutor().execute(() -> runManifestPublishAttempt(0));
    }

    private void runManifestPublishAttempt(final int attempt) {
        final TrustManifest target;
        synchronized (manifestPublishLock) {
            target = pendingPublishManifest;
            if (target == null) {
                manifestPublishLoopRunning = false;
                return;
            }
        }
        if (mXmppConnectionService == null) {
            synchronized (manifestPublishLock) { manifestPublishLoopRunning = false; }
            return;
        }
        final im.conversations.android.xmpp.model.x3dhpq.trustmanifest.TrustManifestItem item =
                new im.conversations.android.xmpp.model.x3dhpq.trustmanifest.TrustManifestItem();
        item.setContent(target.marshal());
        final Iq iq =
                mXmppConnectionService
                        .getIqGenerator()
                        .generateX3dhpqPublishTrustManifest(item, "current");
        // sendIqPacket only calls back on a response or on disconnect (Iq.Type.TIMEOUT); a
        // lost response while still connected would hang forever, so we arm our OWN timeout.
        final java.util.concurrent.atomic.AtomicBoolean settled =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        final java.util.concurrent.ScheduledFuture<?> timeout =
                manifestPublishExecutor().schedule(
                        () -> {
                            if (settled.compareAndSet(false, true)) {
                                onManifestPublishResult(target, attempt, false);
                            }
                        },
                        MANIFEST_PUBLISH_TIMEOUT_MS,
                        java.util.concurrent.TimeUnit.MILLISECONDS);
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    if (!settled.compareAndSet(false, true)) return;
                    timeout.cancel(false);
                    final boolean ok = response.getType() == Iq.Type.RESULT;
                    manifestPublishExecutor().execute(
                            () -> onManifestPublishResult(target, attempt, ok));
                });
    }

    private void onManifestPublishResult(
            final TrustManifest target, final int attempt, final boolean ok) {
        synchronized (manifestPublishLock) {
            // Superseded by a newer version while we were publishing → restart on the newest.
            if (pendingPublishManifest != null
                    && Long.compareUnsigned(pendingPublishManifest.getVersion(), target.getVersion()) > 0) {
                manifestPublishExecutor().execute(() -> runManifestPublishAttempt(0));
                return;
            }
            if (ok) {
                if (pendingPublishManifest != null
                        && pendingPublishManifest.getVersion() == target.getVersion()) {
                    pendingPublishManifest = null; // latest confirmed → loop exits
                    manifestPublishLoopRunning = false;
                    Log.d(Config.LOGTAG, LOGPREFIX + ": trustmanifest published + confirmed (version="
                            + Long.toUnsignedString(target.getVersion()) + ")");
                    return;
                }
                manifestPublishExecutor().execute(() -> runManifestPublishAttempt(0));
                return;
            }
            final int next = attempt + 1;
            if (next >= MANIFEST_PUBLISH_DELAYS_MS.length) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest version "
                        + Long.toUnsignedString(target.getVersion())
                        + " NOT confirmed after retries; will reconcile on next connect");
                pendingPublishManifest = null; // drop; reconcile handles it later
                manifestPublishLoopRunning = false;
                return;
            }
            Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest version "
                    + Long.toUnsignedString(target.getVersion())
                    + " not confirmed (attempt " + next + ") — retrying");
            manifestPublishExecutor().schedule(
                    () -> runManifestPublishAttempt(next),
                    MANIFEST_PUBLISH_DELAYS_MS[next],
                    java.util.concurrent.TimeUnit.MILLISECONDS);
        }
    }

    /**
     * The §C gate: verify a received manifest (AIK pin, version/rollback/fork guard, fold,
     * head signature under a folded device), then write the folded device set into the
     * trust tables the fanout reads. Never wipes existing trust on a bad manifest (keeps
     * last good); an owner with no manifest simply stays on the devicelist path (fallback).
     */
    void handleInboundTrustManifest(final Jid ownerBareJid, final byte[] bytes) {
        if (db == null || ownerBareJid == null || bytes == null || bytes.length == 0) return;
        final String accountUuid = account != null ? account.getUuid() : "test";
        final String owner = ownerBareJid.asBareJid().toString();
        final long now = System.currentTimeMillis() / 1000L;

        final TrustManifest m = TrustManifest.unmarshal(bytes);
        if (m == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest from " + owner
                    + " failed to unmarshal; keeping devicelist fallback");
            return;
        }

        final boolean isOwn =
                account != null && ownerBareJid.asBareJid().equals(account.getJid().asBareJid());

        // §C.2 AIK pinning (TOFU). Own account → the account AIK pub; peer → the TOFU-pinned
        // peer AIK (reuse the bundle-pin store). First sight of a peer pins m.aik. REJECT an
        // account-root swap (m.aik != pinned).
        AccountIdentityPub pinned = null;
        if (isOwn) {
            final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                    db.loadX3dhpqAccountIdentity(accountUuid);
            if (aikRow != null && aikRow.aikPub() != null && aikRow.aikPub().length > 0) {
                try {
                    pinned = AccountIdentityPub.unmarshal(aikRow.aikPub());
                } catch (final Exception ignore) {
                    pinned = null;
                }
            }
        } else {
            pinned = resolvePinnedPeerAik(accountUuid, owner);
        }
        if (pinned == null) {
            // First-use / bootstrap: pin the manifest's own AIK (own account with no AIK row
            // yet, or a peer with no cached bundle). The genesis edge is still AIK-verified
            // inside fold() below, so this only defers the account-root swap check.
            pinned = m.getAik();
        }
        // Task #55 STRICT AIK-lineage branch. This MUST come BEFORE the version/rollback
        // guard below: an account reset roots a FRESH genesis at version=1 under a DIFFERENT
        // AIK — that is a re-pin event, NOT a rollback of the old-AIK lineage, so it must
        // never be judged against the old lineage's last-seen version. On an AIK mismatch we
        // do NOT silently reject; we route to the same "same-JID-different-AIK / devicelist
        // fork" re-verify UX and REFUSE traffic under the new AIK until the user manually
        // re-verifies/re-pairs. Even a VALID RotationPointer would still require manual
        // re-verify (STRICT / RESET-ONLY: no auto-adopt, incl. the user's own devices).
        if (!Arrays.equals(pinned.marshal(), m.getAik().marshal())) {
            if (isOwn) {
                // Our OWN account manifest arrived under a different AIK than the one this
                // device holds — i.e. another of our devices performed an account reset.
                // STRICT: do NOT auto-adopt; this device stays on its current identity until
                // the user re-pairs it (§10.6.6). Keep last good.
                Log.w(Config.LOGTAG, LOGPREFIX + ": OWN trustmanifest arrived under a DIFFERENT"
                        + " AIK (account reset on another device); NOT auto-adopting — re-pair"
                        + " this device to join the new identity (STRICT)");
            } else {
                Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest from " + owner
                        + " has a DIFFERENT account AIK than pinned (account reset / same-JID"
                        + " different-AIK); pausing traffic until explicit re-verify (STRICT)");
                try {
                    flagIdentityReconstructionEvent(ownerBareJid);
                } catch (final Exception ignored) {
                    // best-effort UX signal; never let it change the refuse decision
                }
            }
            return;
        }

        // §C.3 version / rollback / fork guard (mirror deviceListGate §8.5). Reached only
        // WITHIN the same AIK lineage (the aik-mismatch branch above already handled a
        // re-pin), so a legitimate reset's version=1 is never mistaken for a rollback.
        final DatabaseBackend.X3dhpqManifestStateRow state =
                db.loadX3dhpqManifestState(accountUuid, owner);
        final long lastSeen = state != null ? state.version() : -1L;
        final long version = m.getVersion();
        final byte[] blobHash = m.computeHash();
        if (state != null && Long.compareUnsigned(version, lastSeen) < 0) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest rollback from " + owner
                    + " (version " + Long.toUnsignedString(version) + " < last-seen "
                    + Long.toUnsignedString(lastSeen) + "); rejecting");
            return;
        }
        if (state != null && version == lastSeen && !Arrays.equals(state.blobHash(), blobHash)) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest fork from " + owner
                    + " (same version, different content); rejecting");
            return;
        }

        // §C.4 fold. An invalid genesis ⇒ empty fold ⇒ treat as REJECT (keep last good).
        final java.util.Map<Long, DeviceCertificate> folded = TrustManifest.fold(m);
        if (folded.isEmpty()) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest from " + owner
                    + " folded to an EMPTY set (invalid genesis); keeping last good");
            return;
        }

        // §C.5 head signature: REQUIRE the head verify under some currently-folded device's
        // DIK (publisher is a currently-trusted device).
        boolean headOk = false;
        for (final DeviceCertificate dc : folded.values()) {
            if (m.verifyHead(dc.getDikPubEd25519(), dc.getDikPubMLDSA())) {
                headOk = true;
                break;
            }
        }
        if (!headOk) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": trustmanifest from " + owner
                    + " head signature does not match any folded device (non-member publisher);"
                    + " rejecting");
            return;
        }

        // §C.6 accept: persist state + write the folded set into the trust tables.
        db.putX3dhpqManifestState(accountUuid, owner, version, blobHash, m.marshal(), now);
        writeFoldedTrustSet(accountUuid, ownerBareJid, isOwn, folded, now);
        Log.d(Config.LOGTAG, LOGPREFIX + ": accepted trustmanifest from " + owner
                + " version=" + Long.toUnsignedString(version) + " → " + folded.size()
                + " trusted device(s)");
    }

    /**
     * Writes a folded device set into the trust tables the send-time fanout reads
     * (contract §C.6): {@code x3dhpq_remote_device} for every folded id (+ prune), and for
     * the OWN account also {@code x3dhpq_co_account_device} for every non-local folded id
     * (+ prune) plus a re-baseline of the shrink guard's committed set. Also schedules a
     * bundle fetch for any peer folded device we have no bundle for yet.
     */
    private void writeFoldedTrustSet(
            final String accountUuid,
            final Jid ownerBareJid,
            final boolean isOwn,
            final java.util.Map<Long, DeviceCertificate> folded,
            final long now) {
        final String owner = ownerBareJid.asBareJid().toString();
        final java.util.Set<Integer> localIds = new java.util.HashSet<>();
        if (isOwn) {
            for (final DatabaseBackend.X3dhpqLocalDeviceRow row :
                    db.listX3dhpqLocalDevices(accountUuid)) {
                localIds.add(row.deviceId());
            }
        }
        final java.util.Set<Integer> foldedIds = new java.util.HashSet<>();
        final java.util.Set<Integer> coFoldedIds = new java.util.HashSet<>();
        for (final java.util.Map.Entry<Long, DeviceCertificate> en : folded.entrySet()) {
            final int id = (int) (long) en.getKey();
            final DeviceCertificate dc = en.getValue();
            final byte[] dcBytes = dc.marshal();
            db.putX3dhpqRemoteDevice(accountUuid, owner, id, dcBytes, now);
            foldedIds.add(id);
            if (isOwn) {
                if (!localIds.contains(id)) {
                    db.putX3dhpqCoAccountDevice(accountUuid, id, dcBytes, dc.getCreatedAt(),
                            dc.getFlags() & 0xff);
                    coFoldedIds.add(id);
                }
            } else if (db.loadX3dhpqRemoteBundle(accountUuid, owner, id) == null
                    && mXmppConnectionService != null) {
                requestPeerBundle(ownerBareJid, id);
            }
        }
        db.pruneX3dhpqRemoteDevicesNotIn(accountUuid, owner, foldedIds);
        if (isOwn) {
            db.pruneX3dhpqCoAccountDevicesNotIn(accountUuid, coFoldedIds);
            db.putX3dhpqCommittedDevices(accountUuid, foldedIds);
        }
    }

    /** Loads the currently-accepted own manifest from persisted state, or null. */
    private TrustManifest loadCurrentOwnManifest(final String accountUuid, final String ownBare) {
        final DatabaseBackend.X3dhpqManifestStateRow state =
                db.loadX3dhpqManifestState(accountUuid, ownBare);
        if (state == null || state.blob() == null || state.blob().length == 0) return null;
        return TrustManifest.unmarshal(state.blob());
    }

    /** True iff this device holds the account AIK private key (the primary). */
    private boolean holdsAikPriv() {
        if (db == null || account == null) return false;
        final DatabaseBackend.X3dhpqAccountIdentityRow row =
                db.loadX3dhpqAccountIdentity(account.getUuid());
        return row != null && row.aikPriv() != null && row.aikPriv().length > 0;
    }

    /**
     * Task #65 (mirrors Dino {@code build_snapshot_manifest}): build a COMPACT, AIK-anchored
     * snapshot manifest asserting exactly the CURRENT {@code members} (device_id → DC). We do
     * NOT track history — each published manifest is a fresh snapshot of the current
     * membership (size bounded by the number of devices, NOT by how many pair/revoke
     * operations happened), chained to the previous version only by {@code prevHash}. The
     * genesis edge (THIS device) is AIK-signed and every OTHER member is a DIK-signed ADD
     * (DC re-issued under this device's DIK) authored by THIS device, so the whole set is
     * verifiably derived from the account AIK. The head is signed under this device's DIK.
     * Requires AIK_priv (the primary maintains the snapshot); returns {@code null} otherwise.
     * {@code members} need not contain self (this device is always the genesis).
     */
    private TrustManifest buildSnapshotManifest(
            final java.util.Map<Long, DeviceCertificate> members,
            final long version,
            final byte[] prevHash) {
        final String accountUuid = account.getUuid();
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null || aikRow.aikPriv() == null || aikRow.aikPriv().length == 0) {
            return null; // not the primary → cannot root an AIK-signed genesis
        }
        final AccountIdentityKey aik;
        final AccountIdentityPub aikPub;
        try {
            aik = AccountIdentityKey.unmarshal(aikRow.aikPriv());
            aikPub = AccountIdentityPub.unmarshal(aikRow.aikPub());
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": buildSnapshotManifest — bad AIK material: "
                    + e.getMessage());
            return null;
        }
        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) return null;
        final DatabaseBackend.X3dhpqLocalDeviceRow selfRow = localRows.get(0);
        final long selfId = selfRow.deviceId() & 0xffffffffL;
        final DeviceIdentityKey selfDik;
        final DeviceCertificate selfDc;
        try {
            selfDik = DeviceIdentityKey.unmarshal(selfRow.dikPriv());
            selfDc = DeviceCertificate.unmarshal(selfRow.dc());
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": buildSnapshotManifest — bad self device material: "
                    + e.getMessage());
            return null;
        }
        final long ts = System.currentTimeMillis() / 1000L;
        final byte[] selfDcHash = X3dhpqCrypto.sha512(selfDc.marshal());

        // Genesis entry (AIK-signed): this device roots the snapshot. v2 = no lamport/parents.
        final TrustEntry genesis = TrustEntry.signNew(
                TrustEntry.ACTION_ADD, selfId, selfDc,
                selfId, selfDcHash, ts, aik.getPrivEd25519(), aik.getPrivMLDSA());
        final List<TrustEntry> entries = new ArrayList<>();
        entries.add(genesis);

        // One DIK-signed ADD per OTHER current member (DC re-issued under this device's DIK).
        // Sorted by id for determinism; fold() orders by device_id so this stays Dino-compatible.
        final List<Long> otherIds = new ArrayList<>(members.keySet());
        otherIds.sort(java.util.Comparator.naturalOrder());
        for (final Long idL : otherIds) {
            if (idL == selfId) continue;
            final DeviceCertificate subjectDc = members.get(idL);
            if (subjectDc == null) continue;
            final DeviceCertificate reissued = reissueDcUnderDik(subjectDc, selfDik);
            final TrustEntry add = TrustEntry.signNew(
                    TrustEntry.ACTION_ADD, idL, reissued,
                    selfId, selfDcHash, ts,
                    selfDik.getPrivEd25519(), selfDik.getPrivMLDSA());
            entries.add(add);
        }

        return new TrustManifest(version, prevHash, aikPub, entries, new byte[0], new byte[0])
                .signHead(selfDik.getPrivEd25519(), selfDik.getPrivMLDSA());
    }

    /**
     * Persist a freshly-built OWN snapshot as the accepted local state, write the folded
     * device set into the trust tables the fanout reads, and (single-flight) publish it.
     */
    private void applyAndPublishOwnSnapshot(
            final String accountUuid, final String ownBare, final TrustManifest snap) {
        final long ts = System.currentTimeMillis() / 1000L;
        db.putX3dhpqManifestState(accountUuid, ownBare, snap.getVersion(), snap.computeHash(),
                snap.marshal(), ts);
        writeFoldedTrustSet(accountUuid, account.getJid().asBareJid(), true,
                TrustManifest.fold(snap), ts);
        publishTrustManifest(snap);
    }

    /**
     * §D1 migration / genesis (snapshot model, task #65): on login, if the own trustmanifest
     * node has NO accepted manifest AND this device holds AIK_priv (primary), build a compact
     * snapshot of today's authorized device set (self + devicelist/co-account siblings) and
     * publish it. Idempotent — a no-op once a manifest exists. Never throws to the caller.
     */
    public void maybePublishGenesisManifest() {
        try {
            if (db == null || account == null || mXmppConnectionService == null) return;
            if (isPendingEnrollment()) return; // no AIK held yet
            final String accountUuid = account.getUuid();
            final String ownBare = account.getJid().asBareJid().toString();
            if (db.loadX3dhpqManifestState(accountUuid, ownBare) != null) {
                return; // already have a manifest → adopt/extend, do not rebuild genesis
            }
            // Members = today's authorized union (self + co-account siblings). buildSnapshot
            // makes self the genesis and re-issues the others under this device's DIK.
            final java.util.Map<Long, DeviceCertificate> members = new java.util.HashMap<>();
            for (final java.util.Map.Entry<Long, im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> e :
                    computeUnionDeviceEntries(accountUuid).entrySet()) {
                members.put(e.getKey(), e.getValue().getCert());
            }
            final DatabaseBackend.X3dhpqDeviceListStateRow dlState =
                    db.loadX3dhpqDeviceListState(accountUuid, ownBare);
            final long version = (dlState != null ? dlState.version() : 0L) + 1L;
            final TrustManifest snap = buildSnapshotManifest(members, version, new byte[64]);
            if (snap == null) return; // not the primary (no AIK_priv)
            applyAndPublishOwnSnapshot(accountUuid, ownBare, snap);
            Log.d(Config.LOGTAG, LOGPREFIX + ": published GENESIS snapshot trustmanifest version="
                    + Long.toUnsignedString(version) + " with " + snap.getEntries().size() + " entr(ies)");
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": maybePublishGenesisManifest failed (non-fatal): "
                    + e.getMessage());
        }
    }

    /**
     * §D2 confirmer append (snapshot model, task #65): at pairing confirmation, rebuild a
     * fresh COMPACT snapshot asserting {@code fold(current) ∪ {newcomer}} at version+1 and
     * publish it — NOT an append to an ever-growing log. Requires AIK_priv (the primary
     * maintains the AIK-rooted snapshot; a non-primary edit is deferred to the primary's next
     * publish/reconcile). Returns true if a snapshot was built + published.
     */
    public boolean confirmerAppendDevice(final DeviceCertificate newcomerDc) {
        try {
            if (db == null || account == null || mXmppConnectionService == null || newcomerDc == null) {
                return false;
            }
            if (!holdsAikPriv()) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": confirmerAppendDevice — no AIK_priv; the"
                        + " primary maintains the snapshot manifest (deferred)");
                return false;
            }
            final String accountUuid = account.getUuid();
            final String ownBare = account.getJid().asBareJid().toString();
            TrustManifest m = loadCurrentOwnManifest(accountUuid, ownBare);
            if (m == null) {
                // No manifest yet: build genesis first (idempotent), then re-load.
                maybePublishGenesisManifest();
                m = loadCurrentOwnManifest(accountUuid, ownBare);
            }
            // Current members = the fold of the latest manifest (∅ if we still have none).
            final java.util.Map<Long, DeviceCertificate> members =
                    m != null ? TrustManifest.fold(m) : new java.util.HashMap<>();
            final long baseVer = m != null ? m.getVersion() : 0L;
            final byte[] prevHash = m != null ? m.computeHash() : new byte[64];
            members.put(newcomerDc.getDeviceId() & 0xffffffffL, newcomerDc);

            final TrustManifest snap = buildSnapshotManifest(members, baseVer + 1L, prevHash);
            if (snap == null) return false;
            applyAndPublishOwnSnapshot(accountUuid, ownBare, snap);
            Log.d(Config.LOGTAG, LOGPREFIX + ": confirmer republished snapshot ADD(device="
                    + newcomerDc.getDeviceId() + ") → version=" + Long.toUnsignedString(snap.getVersion())
                    + " members=" + members.size());
            return true;
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": confirmerAppendDevice failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * §D4 revoke (snapshot model, task #65): rebuild a fresh COMPACT snapshot asserting
     * {@code fold(current) \ {target}} at version+1 and publish it. Removal is expressed by
     * the target's ABSENCE from the new snapshot (not a REMOVE edge on a growing log).
     * Requires AIK_priv (the primary maintains the snapshot). A target not currently in the
     * fold is an idempotent no-op. Returns true if a snapshot was built + published.
     *
     * <p>The Phase-0 self-revoke guard lives at the {@link #revokeOwnDevice} call site.
     */
    public boolean confirmerRemoveDevice(final int targetDeviceId) {
        try {
            if (db == null || account == null || mXmppConnectionService == null) {
                return false;
            }
            if (!holdsAikPriv()) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": confirmerRemoveDevice — no AIK_priv; the"
                        + " primary maintains the snapshot manifest (deferred)");
                return false;
            }
            final String accountUuid = account.getUuid();
            final String ownBare = account.getJid().asBareJid().toString();
            TrustManifest m = loadCurrentOwnManifest(accountUuid, ownBare);
            if (m == null) {
                maybePublishGenesisManifest();
                m = loadCurrentOwnManifest(accountUuid, ownBare);
                if (m == null) return false;
            }
            final long targetId = targetDeviceId & 0xffffffffL;
            final java.util.Map<Long, DeviceCertificate> members = TrustManifest.fold(m);
            if (!members.containsKey(targetId)) {
                Log.d(Config.LOGTAG, LOGPREFIX + ": confirmerRemoveDevice — target "
                        + Integer.toUnsignedString(targetDeviceId)
                        + " is not in the current fold; nothing to revoke");
                return false;
            }
            members.remove(targetId);
            final byte[] prevHash = m.computeHash();
            final TrustManifest snap = buildSnapshotManifest(members, m.getVersion() + 1L, prevHash);
            if (snap == null) return false;
            applyAndPublishOwnSnapshot(accountUuid, ownBare, snap);
            Log.d(Config.LOGTAG, LOGPREFIX + ": revoke " + Integer.toUnsignedString(targetDeviceId)
                    + " — republished snapshot version=" + Long.toUnsignedString(snap.getVersion())
                    + " members=" + members.size());
            return true;
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": confirmerRemoveDevice failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Connect-time reconcile + AUTO-COMPACTION (task #65, mirrors Dino ensure_trust_manifest).
     * The server is the authoritative shared copy, so on every connect: (1) if we hold a local
     * manifest with MORE entries than fold members and we hold AIK_priv, rebuild a compact
     * snapshot of the current fold and publish it (version+1) — self-heals a manifest bloated
     * by the append-only era; (2) otherwise fetch the server copy and adopt a newer version,
     * or (re)publish ours when the server is missing it / behind (our last publish's ACK may
     * have been lost). Never throws to the caller.
     */
    public void reconcileOwnManifestOnConnect() {
        try {
            if (db == null || account == null || mXmppConnectionService == null) return;
            if (isPendingEnrollment()) return;
            final String accountUuid = account.getUuid();
            final String ownBare = account.getJid().asBareJid().toString();
            final TrustManifest local = loadCurrentOwnManifest(accountUuid, ownBare);
            if (local == null) return; // no local manifest → genesis/adopt handled elsewhere

            // (1) AUTO-COMPACT a bloated manifest (more entries than current members).
            if (holdsAikPriv()) {
                final java.util.Map<Long, DeviceCertificate> members = TrustManifest.fold(local);
                if (!members.isEmpty() && local.getEntries().size() > members.size()) {
                    final TrustManifest snap =
                            buildSnapshotManifest(members, local.getVersion() + 1L, local.computeHash());
                    if (snap != null) {
                        applyAndPublishOwnSnapshot(accountUuid, ownBare, snap);
                        Log.d(Config.LOGTAG, LOGPREFIX + ": compacted manifest "
                                + local.getEntries().size() + " entries → " + members.size()
                                + " members (version " + Long.toUnsignedString(snap.getVersion()) + ")");
                        return;
                    }
                }
            }

            // (2) RECONCILE with the server: adopt newer, (re)publish if server behind/absent.
            reconcileServerManifest(ownBare, local);
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": reconcileOwnManifestOnConnect failed (non-fatal): "
                    + e.getMessage());
        }
    }

    /** Fetch the server's own-account manifest and adopt-if-ahead / republish-if-behind. */
    private void reconcileServerManifest(final String ownBare, final TrustManifest local) {
        final Jid ownJid = account.getJid().asBareJid();
        final Iq iq =
                mXmppConnectionService.getIqGenerator().generateX3dhpqRequestTrustManifest(ownJid);
        mXmppConnectionService.sendIqPacket(
                account,
                iq,
                response -> {
                    TrustManifest server = null;
                    if (response.getType() == Iq.Type.RESULT) {
                        final Extension payload =
                                extractPubsubPayload(
                                        response,
                                        im.conversations.android.xmpp.model.x3dhpq.trustmanifest
                                                .TrustManifestItem.class);
                        if (payload
                                instanceof
                                im.conversations.android.xmpp.model.x3dhpq.trustmanifest
                                        .TrustManifestItem) {
                            server = TrustManifest.unmarshal(
                                    ((im.conversations.android.xmpp.model.x3dhpq.trustmanifest
                                                    .TrustManifestItem)
                                                    payload)
                                            .asBytes());
                        }
                    }
                    if (server != null
                            && Long.compareUnsigned(server.getVersion(), local.getVersion()) > 0) {
                        handleInboundTrustManifest(ownJid, server.marshal()); // server ahead → adopt
                    } else if (server == null
                            || Long.compareUnsigned(local.getVersion(), server.getVersion()) > 0) {
                        publishTrustManifest(local); // server behind/absent → (re)push ours
                    }
                });
    }

    /**
     * Trust Manifest Phase 2 authorization (task #54): true iff THIS device is currently a
     * trusted member of the account — i.e. its device id is present in the fold of the
     * current own manifest. Any folded device may author a DIK-signed edit (ADD/REMOVE),
     * so this — NOT holding AIK_priv — is the gate for revoke authorship and its UI.
     *
     * <p>Fallback when no manifest exists yet (pre-migration): a non-pending device whose
     * own key row is present is a member via the co-account/devicelist model. Genesis
     * manifest build and devicelist/account-root signing stay AIK_priv-gated elsewhere and
     * are unaffected by this check.
     */
    public boolean localDeviceCanAuthorTrust() {
        if (db == null || account == null) return false;
        if (isPendingEnrollment()) return false;
        final Integer ownId = getOwnDeviceIdOrNull();
        if (ownId == null) return false;
        final String accountUuid = account.getUuid();
        final String ownBare = account.getJid().asBareJid().toString();
        final TrustManifest m = loadCurrentOwnManifest(accountUuid, ownBare);
        if (m != null) {
            try {
                return TrustManifest.fold(m).containsKey(ownId & 0xffffffffL);
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": localDeviceCanAuthorTrust fold failed: "
                        + e.getMessage());
                return false;
            }
        }
        // No manifest yet: trust via existing membership (our own device key row exists).
        for (final DatabaseBackend.X3dhpqLocalDeviceRow row :
                db.listX3dhpqLocalDevices(accountUuid)) {
            if (row.deviceId() == ownId) return true;
        }
        return false;
    }

    /**
     * §D3 newcomer adopt: fetch the account's own trustmanifest, verify+fold, and populate
     * the trust tables. The newcomer sees itself + siblings via the fold once the
     * confirmer's ADD lands; until then it simply has no manifest and stays on the
     * devicelist fallback.
     */
    public void fetchAndAdoptManifest() {
        if (account == null) return;
        requestTrustManifest(account.getJid().asBareJid());
    }

    /** Re-issue a subject device's DC under a new issuer DIK, keeping the subject DIK pubs. */
    private static DeviceCertificate reissueDcUnderDik(
            final DeviceCertificate subject, final DeviceIdentityKey issuerDik) {
        final DeviceCertificate unsigned = new DeviceCertificate(
                subject.getVersion(), subject.getDeviceId(),
                subject.getDikPubEd25519(), subject.getDikPubX25519(), subject.getDikPubMLDSA(),
                subject.getCreatedAt(), subject.getFlags(), new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(issuerDik.getPrivEd25519(), sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(issuerDik.getPrivMLDSA(), sp);
        return new DeviceCertificate(
                subject.getVersion(), subject.getDeviceId(),
                subject.getDikPubEd25519(), subject.getDikPubX25519(), subject.getDikPubMLDSA(),
                subject.getCreatedAt(), subject.getFlags(), sigEd, sigMl);
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
                    + " — possible compromise or rotation; refusing to overwrite.");
            // §10.6.5: surface the identity change (block flag + security notice +
            // light-red conversation mark) so the user must re-verify out-of-band
            // before trusting the new identity, instead of silently dropping it.
            try {
                flagIdentityReconstructionEvent(eu.siacs.conversations.xmpp.Jid.of(peer));
            } catch (final Exception ignored) {
                // best-effort UX signal; never let it block the reject above
            }
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
            // Remember this device as un-encryptable so fan-out skips it instead of
            // deferring every message forever (a stale/forked device that was never
            // re-paired). Revoking it from the manifest is the durable cleanup.
            dcInvalidDevices.add(peer + "/" + deviceId);
            return;
        }
        // DC verified — if this device was previously marked invalid (e.g. it has since
        // been re-paired with an AIK-signed DC), clear the marker so it receives again.
        dcInvalidDevices.remove(peer + "/" + deviceId);

        // verify deviceId in DC matches the bundle's item id
        if ((int) dc.getDeviceId() != deviceId) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: bundle/DC deviceId mismatch: bundle=" + deviceId
                    + " dc=" + dc.getDeviceId());
            return;
        }

        // Parse the remaining key material so we can authenticate it before it is
        // ever stored or used. A malformed bundle is rejected here rather than
        // being persisted and blowing up later at session establishment.
        final BundleData parsed;
        try {
            parsed = BundleParser.fromBundle(bundle);
        } catch (Exception e) {
            Log.w(Config.LOGTAG,
                    "x3dhpq: unparseable bundle from " + peer + "/" + deviceId + ": " + e.getMessage());
            return;
        }

        // Verify the SPK signature against the DC's DIK Ed25519 key (spec §9.1).
        // The SPK is consumed as dh1/dh3 in PQXDH, so an unverified SPK lets an
        // active tamperer (malicious server / MITM on the PEP fetch) inject a
        // bogus pre-key. A bundle whose SPK signature fails MUST be rejected.
        if (parsed.spkSig == null
                || !X3dhpqCrypto.ed25519Verify(dc.getDikPubEd25519(), parsed.spkPub, parsed.spkSig)) {
            Log.e(Config.LOGTAG,
                    "x3dhpq: SPK signature verification FAILED for " + peer + "/" + deviceId
                    + "; rejecting bundle");
            return;
        }

        // Verify the hybrid DIK signature on every KEM pre-key (spec §9.1). The
        // KEM pre-key is the sole carrier of post-quantum (HNDL) confidentiality,
        // so an unsigned or forged KEM pre-key is rejected. A legitimate publisher
        // signs all of them; any failure means tampering, so the whole bundle is
        // rejected — which also guarantees every stored key is valid, so the
        // initiator's get(0) selection at session setup is safe without re-checking.
        // Transitional stance: verify KEM signatures when present, reject only a
        // present-but-invalid (forged) one. A legacy bundle whose KEM pre-keys
        // carry no signatures is accepted so sessions still establish across
        // mixed-version deployments. Re-tighten once all peers publish signed
        // bundles.
        final byte[] dikEd = dc.getDikPubEd25519();
        final byte[] dikMldsa = dc.getDikPubMLDSA();
        for (final BundleData.KemPreKey kem : parsed.kemPreKeys) {
            if (kem.sigEd == null || kem.sigMldsa == null) {
                continue;
            }
            if (!X3dhpqCrypto.ed25519Verify(dikEd, kem.pub, kem.sigEd)
                    || !X3dhpqCrypto.mldsa65Verify(dikMldsa, kem.pub, kem.sigMldsa)) {
                Log.e(Config.LOGTAG,
                        "x3dhpq: KEM pre-key " + kem.id + " signature verification FAILED for "
                        + peer + "/" + deviceId + "; rejecting bundle");
                return;
            }
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
     * True iff {@code dcMarshal} is a well-formed DeviceCertificate whose Ed25519 issuer
     * signature verifies under {@code aikEd25519Pub}. Used as a pre-send guard so we never
     * marshal a certificate into a prekey that the receiver would reject (wolfSSL rc=-229)
     * because it was signed by a different key than the advertised AIK.
     */
    private static boolean dcVerifiesUnderAik(final byte[] dcMarshal, final byte[] aikEd25519Pub) {
        if (dcMarshal == null || dcMarshal.length == 0
                || aikEd25519Pub == null || aikEd25519Pub.length == 0) {
            return false;
        }
        try {
            final DeviceCertificate dc = DeviceCertificate.unmarshal(dcMarshal);
            return X3dhpqCrypto.ed25519Verify(
                    aikEd25519Pub, dc.signedPart(), dc.getSigEd25519());
        } catch (final Exception e) {
            return false;
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

        // Local guard: the DC we are about to marshal into the prekey MUST verify against
        // the AIK we advertise alongside it — the receiver (incl. Dino) rejects a mismatch
        // with wolfSSL rc=-229 and can never build a recv chain, so its group/1:1 messages
        // from us defer forever. Catch that class of bug at the source (e.g. a DIK-delegated
        // DC left over from a half-adopted pairing) rather than only on the remote.
        if (!dcVerifiesUnderAik(localRow.dc(), aikEdPub)) {
            Log.e(Config.LOGTAG, LOGPREFIX
                    + ": outbound prekey DC does not verify against advertised AIK — refusing"
                    + " to send to " + peer + "/" + peerDeviceId
                    + " (re-pair this device to obtain an AIK-signed certificate)");
            return Optional.empty();
        }

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
    // device is self-delimiting via its cert_len. This dedicated builder mirrors
    // core DeviceList.signedPart() (which was fixed to drop the erroneous uint16
    // num_devices field — see DeviceList.java §8.3 note); both now produce the
    // identical Dino/Go-compatible bytes. Do NOT reintroduce num_devices here.
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
     * Extracted from {@link #publishDeviceList(java.util.Set)}: builds the canonical
     * device-id -&gt; {@link im.conversations.x3dhpq.types.DeviceList.DeviceListEntry}
     * union of {@code x3dhpq_local_device} and {@code x3dhpq_co_account_device} (a
     * locally-generated row wins over a co-account entry for the same id). Pure
     * read/derive, no side effects — safe to call from both the devicelist publish
     * path and the §11.8 sealed-tracker publish path so the two never disagree on
     * which devices are currently authorized.
     */
    private java.util.Map<Long, im.conversations.x3dhpq.types.DeviceList.DeviceListEntry>
            computeUnionDeviceEntries(final String accountUuid) {
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
        return byDeviceId;
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

        // Build the canonical core entries from the union (§11.8 reuses this exact
        // union as the sealed tracker's authorized-recipient set, via
        // computeUnionDeviceEntries, so the sealed set always matches the just-
        // published devicelist).
        final java.util.Map<Long, im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> byDeviceId =
                computeUnionDeviceEntries(accountUuid);

        final List<Long> sortedIds = new ArrayList<>(byDeviceId.keySet());
        sortedIds.sort(java.util.Comparator.naturalOrder());

        // §11.7 v1->v2 bridge: idempotently root the device-audit DAG in a genesis
        // Snapshot of TODAY's union, then try to derive the published set from the
        // DAG fold instead. See ensureDeviceAuditGenesis / resolvePublishDeviceIds
        // for the SAFETY FALLBACK that guarantees this never changes the published
        // wire bytes versus the pre-existing union-only logic.
        ensureDeviceAuditGenesis(accountUuid, byDeviceId);
        final List<Long> publishIds = resolvePublishDeviceIds(accountUuid, sortedIds);

        final List<im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> entries =
                new ArrayList<>();
        for (final Long id : publishIds) {
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

        // §11.8: re-seal the device-state tracker whenever the device set changes.
        // Hooked here (the single implementation both publishDeviceList() overloads
        // funnel through) rather than at each call site, so no current or future
        // caller can forget it. Independent PEP item/IQ; failures only log (see the
        // try/catch inside publishSealedDeviceTracker) and never affect the devicelist
        // publish above or the account-bind path.
        publishSealedDeviceTracker();
    }

    /**
     * x3dhpq-xep-draft.md §11.7 v1-&gt;v2 migration bridge / genesis: if this account
     * has a confirmed local AIK + local device but has never recorded a device-audit
     * DAG entry, build and persist a genesis {@code Snapshot} (action=10) asserting
     * TODAY's authorized device set — the same local ∪ co-account union {@link
     * #publishDeviceList(java.util.Set)} already builds — signed by the account AIK.
     * Idempotent: a no-op once any device-audit entry exists for the account. Never
     * throws to the caller; a failure here only means the DAG stays un-rooted for
     * this call and {@link #resolvePublishDeviceIds} keeps using the union fallback
     * — publishing must never be blocked by this bootstrap step.
     *
     * <p>Deliberately skips accounts still in §10.6.1 pending-enrollment (device
     * flagged {@code FLAG_PENDING_ENROLLMENT}): that AIK is tentative and may still
     * be discarded in favour of a primary's AIK adopted via pairing, so it must
     * never become the TOFU-pinned root of this account's device-audit DAG.
     */
    private void ensureDeviceAuditGenesis(
            final String accountUuid,
            final java.util.Map<Long, im.conversations.x3dhpq.types.DeviceList.DeviceListEntry>
                    byDeviceId) {
        if (db == null) return;
        try {
            if (byDeviceId.isEmpty()) return; // nothing to snapshot yet
            if (!db.listX3dhpqDeviceAuditEntries(accountUuid).isEmpty()) {
                return; // already bootstrapped (or has real DAG history) — never re-genesis
            }
            final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                    db.listX3dhpqLocalDevices(accountUuid);
            if (localRows.isEmpty() || LocalKeyBootstrap.isPending(localRows.get(0))) {
                return; // no confirmed local primary identity yet (§10.6.1)
            }
            final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                    db.loadX3dhpqAccountIdentity(accountUuid);
            if (aikRow == null) return; // nothing to sign the genesis entry with

            final AccountIdentityKey aik;
            try {
                aik = AccountIdentityKey.unmarshal(aikRow.aikPriv());
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX
                        + ": cannot load AIK for device-audit genesis (non-fatal): "
                        + e.getMessage());
                return;
            }

            final List<Long> ids = new ArrayList<>(byDeviceId.keySet());
            ids.sort(java.util.Comparator.naturalOrder());
            final List<im.conversations.x3dhpq.types.DeviceAuditEntryV2.SnapshotDevice>
                    snapDevices = new ArrayList<>();
            for (final Long id : ids) {
                final im.conversations.x3dhpq.types.DeviceList.DeviceListEntry e =
                        byDeviceId.get(id);
                snapDevices.add(
                        new im.conversations.x3dhpq.types.DeviceAuditEntryV2.SnapshotDevice(
                                id, e.getCert().marshal()));
            }

            final byte[] ownerAikFp =
                    im.conversations.x3dhpq.types.DeviceAuditEntryV2.aikFp(aik.getPublic());
            final byte[] payload =
                    im.conversations.x3dhpq.types.DeviceAuditEntryV2.buildSnapshotPayload(
                            ownerAikFp, 0L, snapDevices);
            final long authorDeviceId = localRows.get(0).deviceId() & 0xffffffffL;
            final long ts = System.currentTimeMillis() / 1000L;

            final im.conversations.x3dhpq.types.DeviceAuditEntryV2 genesis =
                    im.conversations.x3dhpq.types.DeviceAuditEntryV2.signNew(
                            aik,
                            0L,
                            authorDeviceId,
                            java.util.Collections.emptyList(),
                            im.conversations.x3dhpq.types.DeviceAuditEntryV2.ACTION_SNAPSHOT,
                            payload,
                            ts);
            final String hashHex =
                    im.conversations.x3dhpq.types.DeviceAuditEntryV2.hex(genesis.computeHash());
            db.putX3dhpqDeviceAuditEntry(accountUuid, hashHex, genesis.marshal(), ts);
            Log.i(Config.LOGTAG, LOGPREFIX
                    + ": device-audit DAG genesis Snapshot bootstrapped for " + accountUuid
                    + " (" + snapDevices.size() + " device(s), §11.7)");
        } catch (final Exception e) {
            // Best-effort only; genesis bootstrap must never block a devicelist publish.
            Log.w(Config.LOGTAG, LOGPREFIX
                    + ": device-audit genesis bootstrap failed (non-fatal): " + e.getMessage());
        }
    }

    /**
     * x3dhpq-xep-draft.md §11.7: attempts to derive the published device-id set from
     * the device-audit DAG fold ({@link im.conversations.x3dhpq.types.DeviceDag#recompute}).
     * Returns {@code unionIds} UNCHANGED (the SAFETY FALLBACK) whenever the DAG has
     * no entries, the fold throws, or — critically — the fold's authorized id set
     * does not exactly equal {@code unionIds}.
     *
     * <p>The equality check exists because {@link X3dhpqStanzaBuilder#buildDeviceList}
     * independently rebuilds the wire {@code <devicelist>} straight from the {@code
     * x3dhpq_local_device}/{@code x3dhpq_co_account_device} union — NOT from this
     * method's return value — so if the fold ever disagreed with that union (e.g. a
     * device enrolled by pairing without yet having an AddDevice audit entry, a
     * future phase not yet wired), signing over the fold's id set would produce a
     * SignedPart that does not match the published XML, breaking peer verification.
     * Falling back to the union whenever they disagree keeps the signed bytes and
     * the wire bytes identical to the pre-existing (pre-DAG) behaviour in every case
     * except the one where the fold and the union already agree — i.e. this only
     * changes anything once later phases keep the DAG properly in sync.
     */
    private List<Long> resolvePublishDeviceIds(final String accountUuid, final List<Long> unionIds) {
        if (db == null) return unionIds;
        try {
            final List<DatabaseBackend.X3dhpqDeviceAuditEntryRow> rows =
                    db.listX3dhpqDeviceAuditEntries(accountUuid);
            if (rows.isEmpty()) return unionIds;

            final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                    db.loadX3dhpqAccountIdentity(accountUuid);
            if (aikRow == null) return unionIds;
            final AccountIdentityPub ownAik;
            try {
                ownAik = AccountIdentityPub.unmarshal(aikRow.aikPub());
            } catch (final Exception e) {
                return unionIds;
            }
            final String ownFpHex =
                    im.conversations.x3dhpq.types.DeviceAuditEntryV2.hex(
                            im.conversations.x3dhpq.types.DeviceAuditEntryV2.aikFp(ownAik));

            final im.conversations.x3dhpq.types.DeviceDag dag =
                    new im.conversations.x3dhpq.types.DeviceDag();
            for (final DatabaseBackend.X3dhpqDeviceAuditEntryRow row : rows) {
                dag.ingest(row.entryBlob());
            }
            // Mirrors DeviceDagTest's resolver: the only trusted signer is this
            // account's own (single) AIK, TOFU-pinned at genesis by the DAG itself.
            final im.conversations.x3dhpq.types.DeviceDag.AikResolver resolver =
                    fpHex -> ownFpHex.equals(fpHex) ? ownAik : null;
            final im.conversations.x3dhpq.types.DeviceDag.DeviceState state =
                    dag.recompute(resolver);

            final List<Long> foldIds = new ArrayList<>(state.authorized.keySet());
            foldIds.sort(java.util.Comparator.naturalOrder());
            if (!foldIds.equals(unionIds)) {
                Log.d(Config.LOGTAG, LOGPREFIX
                        + ": device-audit DAG fold " + foldIds + " does not match the current"
                        + " local∪co-account union " + unionIds
                        + " — publishing from the union (SAFETY FALLBACK, §11.7)");
                return unionIds;
            }
            return foldIds;
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX
                    + ": device-audit DAG recompute failed, falling back to the union device"
                    + " set (non-fatal): " + e.getMessage());
            return unionIds;
        }
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

    // =====================================================================================
    // §11.8: Sealed device-state tracker (urn:xmppqr:x3dhpq:devtracker:0)
    //
    // Additive PEP infrastructure on top of the §11.7 DeviceDag fold. Lets an authorized
    // device sync — and a new/revoked device learn an identity already exists — while
    // every OTHER device of the account is offline. "Being able to decrypt the tracker
    // IS the proof of authorization" (§11.8). Every entry point below is best-effort and
    // MUST NOT throw into publishLocalState()/the account-bind path; failures only log.
    // =====================================================================================

    private static final byte[] DEVTRACKER_SIGNED_DOMAIN =
            "X3DHPQ-DevTracker-v1\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] DEVTRACKER_PAYLOAD_DOMAIN =
            "X3DHPQ-DevTracker-Payload-v1\0".getBytes(StandardCharsets.UTF_8);

    public enum TrackerOutcome {
        /** No item published for this account yet — genuinely first-device territory. */
        ABSENT,
        /** Signature verifies (where checkable) and our own &lt;key&gt; copy decrypted. */
        AUTHORIZED,
        /** Present (and signed, where checkable) but our own copy did not decrypt. */
        NOT_DECRYPTABLE,
        /** Present but the hybrid AIK signature failed to verify — ignored, never acted on. */
        INVALID
    }

    /** Throwaway (never persisted) PQXDH sender session + its prekey envelope. */
    private static final class EphemeralPqxdh {
        final Session session;
        final PrekeyEnvelope envelope;

        EphemeralPqxdh(final Session session, final PrekeyEnvelope envelope) {
            this.session = session;
            this.envelope = envelope;
        }
    }

    /** Parsed plaintext devtracker payload (§11.8: folded DeviceState + DAG heads + optional AIK_priv). */
    private static final class DecodedTracker {
        im.conversations.x3dhpq.types.DeviceAuditEntryV2.Snapshot snapshot;
        List<byte[]> heads;
        AccountIdentityKey aikPriv; // nullable
    }

    /**
     * (Re)publishes the §11.8 sealed device-state tracker for THIS account. Call from every
     * place {@link #publishDeviceList()} is called so the sealed recipient set never lags
     * the published devicelist (§11.8: "ANY authorized device re-publishes it on every
     * device-set change, adding/removing recipient copies").
     *
     * <p>Payload = the folded {@code DeviceState} (device_id -&gt; DC, via the exact same
     * §11.7 {@code Snapshot} encoding used for the DAG genesis/migration bridge) + the
     * current device-audit DAG head hashes (self-contained catch-up) + the shared AIK_priv
     * (§11.8 "MAY carry" — this implementation always does, sealed, so a device that lost
     * its local AIK row can recover it). Sealed exactly like a 1:1 pairwise envelope
     * (§9.3/§9.3a): random content key, AES-256-GCM payload, one hybrid X25519+ML-KEM-768
     * {@code &lt;emk&gt;} per authorized device via a FRESH PQXDH "first message" against
     * that device's own published bundle (§11.8: decryptability must not depend on any
     * prior session state) — reusing {@link XmppX3dhpqMessage} end-to-end, exactly the
     * construction {@link #sendSenderChainAnnouncement} already uses for 1:1 envelopes.
     * The whole item is additionally AIK-signed (hybrid), sig placed as the last children
     * of {@code <devtracker>} (mirrors §8.4's devicelist placement).
     */
    public void publishSealedDeviceTracker() {
        if (db == null || account == null || mXmppConnectionService == null) {
            return;
        }
        try {
            if (isPendingEnrollment()) {
                return; // no confirmed AIK yet (§10.6.1) — nothing to sign/seal with
            }
            final String accountUuid = account.getUuid();
            final java.util.Map<Long, im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> byDeviceId =
                    computeUnionDeviceEntries(accountUuid);
            if (byDeviceId.isEmpty()) {
                return;
            }
            final List<Long> ids = new ArrayList<>(byDeviceId.keySet());
            ids.sort(java.util.Comparator.naturalOrder());

            final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                    db.loadX3dhpqAccountIdentity(accountUuid);
            if (aikRow == null) {
                return;
            }
            final AccountIdentityKey aik;
            final AccountIdentityPub aikPub;
            try {
                aik = AccountIdentityKey.unmarshal(aikRow.aikPriv());
                aikPub = AccountIdentityPub.unmarshal(aikRow.aikPub());
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker publish — cannot load AIK: "
                        + e.getMessage());
                return;
            }

            final byte[] plaintext =
                    buildDeviceTrackerPlaintextPayload(accountUuid, byDeviceId, ids, aikPub, aik);
            if (plaintext == null) {
                return;
            }

            final int ownDeviceId = getOwnDeviceId();
            final XmppX3dhpqMessage xmsg = XmppX3dhpqMessage.createOutboundWithRawPayload(
                    account, account.getJid(), ownDeviceId, plaintext);
            xmsg.setPayloadType("devtracker");

            final Jid ownBareJid = account.getJid().asBareJid();
            int sealedCount = 0;
            boolean anyMissing = false;
            for (final Long id : ids) {
                final int deviceId = id.intValue();
                final EphemeralPqxdh eph = establishEphemeralSelfSession(deviceId);
                if (eph == null) {
                    anyMissing = true;
                    continue;
                }
                final PrekeyEnvelope pe = eph.envelope;
                final XmppX3dhpqMessage.PrekeyMetadata pm = pe != null
                        ? new XmppX3dhpqMessage.PrekeyMetadata(
                                pe.ephemeralPub, pe.opkId, pe.kemKeyId, pe.kemCiphertext,
                                pe.dcMarshal, pe.aikEd25519Pub, pe.aikMldsaPub)
                        : null;
                // isFirst=true always: every seal is a fresh, self-contained PQXDH message.
                xmsg.addRecipient(ownBareJid, deviceId, eph.session, true, pm);
                sealedCount++;
            }
            if (sealedCount == 0) {
                Log.d(Config.LOGTAG, LOGPREFIX + ": devtracker publish deferred — no recipient"
                        + " bundle cached yet; bundle fetch(es) kicked off, will retry on the"
                        + " next device-set-change publish (§11.8)");
                return;
            }

            final Envelope env = xmsg.toExtension();
            final DevTracker tracker = new DevTracker();
            tracker.setSenderDevice(ownDeviceId);
            tracker.setSenderJid(ownBareJid.toString());
            tracker.setTs(env.getTs());
            for (final Key k : env.getKeys()) {
                tracker.addKey(k);
            }
            tracker.setPayload(env.getPayload());
            final long version = nextTrackerVersion(accountUuid);
            tracker.setVersion(version);
            tracker.setIssuedAt(System.currentTimeMillis() / 1000L);

            final byte[] signedPart = deviceTrackerSignedPart(tracker);
            tracker.setSig(X3dhpqCrypto.ed25519Sign(aik.getPrivEd25519(), signedPart));
            tracker.setMldsaSig(X3dhpqCrypto.mldsa65Sign(aik.getPrivMLDSA(), signedPart));

            final boolean missingRecipients = anyMissing;
            final int finalSealedCount = sealedCount;
            final int totalIds = ids.size();
            final Iq iq = mXmppConnectionService.getIqGenerator()
                    .generateX3dhpqPublishDevTracker(tracker, "current");
            mXmppConnectionService.sendIqPacket(account, iq, response -> {
                if (response.getType() == Iq.Type.ERROR) {
                    Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker publish failed: " + response);
                } else {
                    Log.d(Config.LOGTAG, LOGPREFIX + ": devtracker published (§11.8), "
                            + finalSealedCount + "/" + totalIds + " recipient(s) sealed"
                            + (missingRecipients
                                    ? ", some bundles still missing — will re-seal later"
                                    : ""));
                }
            });
        } catch (final Exception e) {
            // Guardrail: sealing/tracker failures must only log, never throw into the
            // devicelist publish / account-bind path.
            Log.w(Config.LOGTAG, LOGPREFIX + ": publishSealedDeviceTracker failed (non-fatal,"
                    + " §11.8): " + e.getMessage());
        }
    }

    /**
     * §11.8: runs a FRESH PQXDH initiation against {@code deviceId}'s currently-cached own-
     * account bundle (kicking off a fetch and returning {@code null} if not yet cached — the
     * caller should just skip this recipient this round; the next device-set-change publish
     * retries it). Deliberately does NOT persist the resulting {@link Session} via {@code
     * db.putX3dhpqSession} — unlike {@link #establishOutboundSession}, which this otherwise
     * mirrors, persisting here would silently clobber whatever live pairwise session is
     * already used for ordinary self-copy message fan-out to the very same
     * (accountUuid, ownBareJid, deviceId) slot (see {@link #addRecipientDevices}), corrupting
     * that Double-Ratchet's state on both sides. The tracker seal is a one-shot, self-
     * contained "first message" envelope, never an ongoing ratcheted conversation, so a
     * throwaway Session per publish is correct and safe.
     */
    private EphemeralPqxdh establishEphemeralSelfSession(final int deviceId) {
        if (db == null || account == null) {
            return null;
        }
        final String accountUuid = account.getUuid();
        final Jid ownBareJid = account.getJid().asBareJid();

        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                db.loadX3dhpqRemoteBundle(accountUuid, ownBareJid.toString(), deviceId);
        if (row == null || row.bundleXml() == null || row.bundleXml().length == 0) {
            requestPeerBundle(ownBareJid, deviceId);
            return null;
        }
        final BundleData peerBundle;
        try {
            peerBundle = BundleParser.fromBundle(parseBundleXml(row.bundleXml()));
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker seal — failed to parse own bundle"
                    + " for device " + deviceId + ": " + e.getMessage());
            return null;
        }

        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) {
            return null;
        }
        final DatabaseBackend.X3dhpqLocalDeviceRow localRow = localRows.get(0);
        final DeviceIdentityKey dik;
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow;
        final AccountIdentityPub aikPub;
        try {
            dik = DeviceIdentityKey.unmarshal(localRow.dikPriv());
            aikRow = db.loadX3dhpqAccountIdentity(accountUuid);
            if (aikRow == null) {
                return null;
            }
            aikPub = AccountIdentityPub.unmarshal(aikRow.aikPub());
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker seal — failed to load local keys: "
                    + e.getMessage());
            return null;
        }

        // Same guard as establishOutboundSession: never advertise a DC that fails to
        // verify against the AIK we ship with it (rc=-229 on the receiver otherwise).
        if (!dcVerifiesUnderAik(localRow.dc(), aikPub.getPubEd25519())) {
            Log.e(Config.LOGTAG, LOGPREFIX
                    + ": devtracker seal — outbound prekey DC does not verify against advertised"
                    + " AIK for own device " + deviceId + " — refusing to send (re-pair)");
            return null;
        }

        final PqxdhResult result = PqxdhInitiator.initiate(
                dik.getPrivX25519(), dik.getPubX25519(), dik.getPubEd25519(),
                localRow.dc(), aikPub.getPubEd25519(), aikPub.getPubMLDSA(),
                peerBundle, X3dhpqCrypto.HKDF_SHA512);

        final Session session = Session.fromPqxdhSenderWithPeerDh(result, peerBundle.spkPub);
        return new EphemeralPqxdh(session, result.getEnvelope());
    }

    /** Monotonic per-account devtracker version counter, cached in prefs (no schema change). */
    private long nextTrackerVersion(final String accountUuid) {
        if (mXmppConnectionService == null) {
            return 1L;
        }
        final android.content.SharedPreferences prefs =
                androidx.preference.PreferenceManager.getDefaultSharedPreferences(
                        mXmppConnectionService);
        final String key = "x3dhpq_devtracker_version_" + accountUuid;
        final long next = prefs.getLong(key, 0L) + 1L;
        prefs.edit().putLong(key, next).apply();
        return next;
    }

    /**
     * Builds the §11.8 plaintext devtracker payload: domain separator | u32-len-prefixed
     * §11.7 {@code Snapshot} (folded DeviceState) | u32 head-count + u32-len-prefixed DAG
     * head hashes | 1-byte has-AIK-priv flag + (if set) u32-len-prefixed {@code
     * AccountIdentityKey.marshal()}. This exact framing is internal to this client's §11.8
     * implementation (the XEP draft does not pin a byte layout for the payload, only for
     * the outer seal); see the porting notes for cross-client alignment.
     */
    private byte[] buildDeviceTrackerPlaintextPayload(
            final String accountUuid,
            final java.util.Map<Long, im.conversations.x3dhpq.types.DeviceList.DeviceListEntry> byDeviceId,
            final List<Long> ids,
            final AccountIdentityPub ownAikPub,
            final AccountIdentityKey aikToEmbed) {
        try {
            final byte[] ownerAikFp =
                    im.conversations.x3dhpq.types.DeviceAuditEntryV2.aikFp(ownAikPub);
            final List<im.conversations.x3dhpq.types.DeviceAuditEntryV2.SnapshotDevice> snapDevices =
                    new ArrayList<>();
            for (final Long id : ids) {
                final im.conversations.x3dhpq.types.DeviceList.DeviceListEntry e = byDeviceId.get(id);
                if (e == null) {
                    continue;
                }
                snapDevices.add(new im.conversations.x3dhpq.types.DeviceAuditEntryV2.SnapshotDevice(
                        id, e.getCert().marshal()));
            }
            final byte[] snapshot = im.conversations.x3dhpq.types.DeviceAuditEntryV2
                    .buildSnapshotPayload(ownerAikFp, 0L, snapDevices);

            final im.conversations.x3dhpq.types.DeviceDag dag =
                    new im.conversations.x3dhpq.types.DeviceDag();
            for (final DatabaseBackend.X3dhpqDeviceAuditEntryRow row :
                    db.listX3dhpqDeviceAuditEntries(accountUuid)) {
                dag.ingest(row.entryBlob());
            }
            final List<byte[]> heads = dag.currentHeads();

            final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            out.write(DEVTRACKER_PAYLOAD_DOMAIN);
            writeU32(out, snapshot.length);
            out.write(snapshot);
            writeU32(out, heads.size());
            for (final byte[] h : heads) {
                writeU32(out, h.length);
                out.write(h);
            }
            if (aikToEmbed != null) {
                out.write(1);
                final byte[] aikBlob = aikToEmbed.marshal();
                writeU32(out, aikBlob.length);
                out.write(aikBlob);
            } else {
                out.write(0);
            }
            return out.toByteArray();
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": buildDeviceTrackerPlaintextPayload failed: "
                    + e.getMessage());
            return null;
        }
    }

    private static void writeU32(final java.io.ByteArrayOutputStream out, final int v) {
        out.write((v >>> 24) & 0xff);
        out.write((v >>> 16) & 0xff);
        out.write((v >>> 8) & 0xff);
        out.write(v & 0xff);
    }

    /** Inverse of {@link #buildDeviceTrackerPlaintextPayload}; throws on malformed input. */
    private static DecodedTracker parseDeviceTrackerPlaintextPayload(final byte[] plaintext) {
        final ByteBuffer buf = ByteBuffer.wrap(plaintext);
        final byte[] domain = new byte[DEVTRACKER_PAYLOAD_DOMAIN.length];
        buf.get(domain);
        if (!Arrays.equals(domain, DEVTRACKER_PAYLOAD_DOMAIN)) {
            throw new IllegalArgumentException("bad devtracker payload domain separator");
        }
        final int snapLen = buf.getInt();
        final byte[] snapBytes = new byte[snapLen];
        buf.get(snapBytes);
        final DecodedTracker out = new DecodedTracker();
        out.snapshot = im.conversations.x3dhpq.types.DeviceAuditEntryV2.parseSnapshot(snapBytes);
        final int headCount = buf.getInt();
        out.heads = new ArrayList<>(headCount);
        for (int i = 0; i < headCount; i++) {
            final int hLen = buf.getInt();
            final byte[] h = new byte[hLen];
            buf.get(h);
            out.heads.add(h);
        }
        final byte hasAik = buf.get();
        if (hasAik != 0) {
            final int aikLen = buf.getInt();
            final byte[] aikBytes = new byte[aikLen];
            buf.get(aikBytes);
            out.aikPriv = AccountIdentityKey.unmarshal(aikBytes);
        }
        return out;
    }

    /**
     * §11.8 outer SignedPart: domain separator | version(u64) | issued_at(u64) |
     * SHA-256(payload ciphertext) | key-count(u32) | SHA-256(canonical per-recipient
     * key digest, sorted by rid ascending). Hashing the bulk content (rather than
     * inlining it) keeps the signed input small and fixed-size while still binding the
     * signature to every byte actually published.
     */
    private static byte[] deviceTrackerSignedPart(final DevTracker tracker) {
        final long version = parseUnsignedLongOrZero(tracker.getVersion());
        final long issuedAt = parseLongOrZero(tracker.getIssuedAt());
        final byte[] payloadBytes =
                tracker.getPayload() != null ? tracker.getPayload().asBytes() : new byte[0];
        final byte[] payloadHash = X3dhpqCrypto.SHA256.hash(payloadBytes);

        final List<Key> keys = new ArrayList<>(tracker.getKeys());
        keys.sort(java.util.Comparator.comparingInt(
                k -> k.getRecipientDeviceId() != null ? k.getRecipientDeviceId() : 0));
        final java.io.ByteArrayOutputStream keyBytes = new java.io.ByteArrayOutputStream();
        for (final Key k : keys) {
            final int rid = k.getRecipientDeviceId() != null ? k.getRecipientDeviceId() : 0;
            writeU32(keyBytes, rid);
            final byte[] hdr = k.getHdr() != null ? k.getHdr().asBytes() : new byte[0];
            final byte[] emk = k.getEmk() != null ? k.getEmk().asBytes() : new byte[0];
            writeU32(keyBytes, hdr.length);
            keyBytes.write(hdr, 0, hdr.length);
            writeU32(keyBytes, emk.length);
            keyBytes.write(emk, 0, emk.length);
        }
        final byte[] keysHash = X3dhpqCrypto.SHA256.hash(keyBytes.toByteArray());

        final ByteBuffer out = ByteBuffer.allocate(
                DEVTRACKER_SIGNED_DOMAIN.length + 8 + 8 + payloadHash.length + 4 + keysHash.length);
        out.put(DEVTRACKER_SIGNED_DOMAIN);
        out.putLong(version);
        out.putLong(issuedAt);
        out.put(payloadHash);
        out.putInt(keys.size());
        out.put(keysHash);
        return out.array();
    }

    private static long parseLongOrZero(final String s) {
        try {
            return s == null ? 0L : Long.parseLong(s);
        } catch (final NumberFormatException e) {
            return 0L;
        }
    }

    private static long parseUnsignedLongOrZero(final String s) {
        try {
            return s == null ? 0L : Long.parseUnsignedLong(s);
        } catch (final NumberFormatException e) {
            return 0L;
        }
    }

    /**
     * §11.8 login-time presence check: used to ENHANCE {@link #resolvePendingEnrollment()}.
     * Fetches the account's own tracker item and reports only whether one is published —
     * "present" is itself already the "an account identity already exists" signal for a
     * device with no AIK to verify against yet, mirroring how the pre-existing devicelist-
     * emptiness fallback check already works (no signature check either).
     */
    private void fetchDeviceTrackerPresence(final java.util.function.Consumer<Boolean> onResult) {
        if (db == null || account == null || mXmppConnectionService == null) {
            onResult.accept(false);
            return;
        }
        final Jid ownBareJid = account.getJid().asBareJid();
        final Iq iq = mXmppConnectionService.getIqGenerator().generateX3dhpqRequestDevTracker(ownBareJid);
        mXmppConnectionService.sendIqPacket(account, iq, response -> {
            boolean present = false;
            try {
                if (response.getType() == Iq.Type.RESULT) {
                    final Extension payload = extractPubsubPayload(response, DevTracker.class);
                    present = payload instanceof DevTracker;
                }
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker presence fetch failed (non-fatal,"
                        + " §11.8): " + e.getMessage());
            }
            onResult.accept(present);
        });
    }

    /**
     * §11.8 login-time check for an ALREADY-ENROLLED device (offline revocation
     * detection): fetches the tracker, verifies the hybrid AIK signature against our own
     * pinned AIK, and attempts to decrypt our own {@code &lt;key&gt;} copy. Sets the
     * {@link #isDisabledByTrackerRevocation()} flag consumed by the device-management UI.
     * No-op while {@link #isPendingEnrollment()} (that case is handled by {@link
     * #resolvePendingEnrollment()}'s tracker-presence check instead) or if nothing is
     * published yet (this login's {@link #publishSealedDeviceTracker()} call will create
     * it).
     */
    public void checkDeviceTrackerForRevocation() {
        if (db == null || account == null || mXmppConnectionService == null) {
            return;
        }
        if (isPendingEnrollment()) {
            return;
        }
        final Jid ownBareJid = account.getJid().asBareJid();
        final Iq iq = mXmppConnectionService.getIqGenerator().generateX3dhpqRequestDevTracker(ownBareJid);
        mXmppConnectionService.sendIqPacket(account, iq, response -> {
            try {
                if (response.getType() != Iq.Type.RESULT) {
                    return;
                }
                final Extension payload = extractPubsubPayload(response, DevTracker.class);
                if (!(payload instanceof DevTracker)) {
                    return; // absent — publishSealedDeviceTracker() will create it this login
                }
                interpretDeviceTrackerSafely((DevTracker) payload);
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker revocation check failed"
                        + " (non-fatal, §11.8): " + e.getMessage());
            }
        });
    }

    /** try/catch wrapper around {@link #interpretDeviceTracker} — never throws to callers. */
    private void interpretDeviceTrackerSafely(final DevTracker tracker) {
        try {
            final TrackerOutcome outcome = interpretDeviceTracker(tracker);
            switch (outcome) {
                case AUTHORIZED:
                    setTrackerRevokedFlag(false);
                    break;
                case NOT_DECRYPTABLE:
                    Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker present + AIK-signed but our"
                            + " own <key> copy did not decrypt — treating as revoked (§11.8)");
                    setTrackerRevokedFlag(true);
                    break;
                case INVALID:
                    Log.w(Config.LOGTAG, LOGPREFIX + ": devtracker AIK signature did not verify"
                            + " — ignoring (possible tamper/downgrade, §11.8)");
                    break;
                case ABSENT:
                default:
                    break;
            }
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": interpretDeviceTrackerSafely failed (non-fatal,"
                    + " §11.8): " + e.getMessage());
        }
    }

    /**
     * Core §11.8 interpretation: verifies the hybrid AIK signature (against our own
     * pinned AIK — always available here since callers only reach this once enrolled) and
     * attempts to decrypt our own {@code &lt;key&gt;} copy exactly like an inbound 1:1
     * message (see {@link eu.siacs.conversations.parser.MessageParser}), reusing {@link
     * #acceptInboundSessionAsSession}. A throwaway {@link Envelope} carries the tracker's
     * keys/payload into {@link XmppX3dhpqMessage#fromExtension} without modifying the
     * shared {@code Envelope} class.
     */
    private TrackerOutcome interpretDeviceTracker(final DevTracker tracker) {
        if (db == null || account == null) {
            return TrackerOutcome.ABSENT;
        }
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(account.getUuid());
        AccountIdentityPub aikPub = null;
        if (aikRow != null) {
            try {
                aikPub = AccountIdentityPub.unmarshal(aikRow.aikPub());
            } catch (final Exception ignored) {
                // aikPub stays null; treated as "cannot verify" below
            }
        }
        if (aikPub == null) {
            return TrackerOutcome.NOT_DECRYPTABLE;
        }

        final byte[] signedPart = deviceTrackerSignedPart(tracker);
        final Sig sig = tracker.getSig();
        final MldsaSig mldsaSig = tracker.getMldsaSig();
        final boolean sigOk = sig != null && mldsaSig != null
                && X3dhpqCrypto.ed25519Verify(aikPub.getPubEd25519(), signedPart, sig.asBytes())
                && X3dhpqCrypto.mldsa65Verify(aikPub.getPubMLDSA(), signedPart, mldsaSig.asBytes());
        if (!sigOk) {
            return TrackerOutcome.INVALID;
        }

        final Integer ownDeviceId = getOwnDeviceIdOrNull();
        if (ownDeviceId == null) {
            return TrackerOutcome.NOT_DECRYPTABLE;
        }
        try {
            final Envelope tmp = new Envelope();
            tmp.setSenderDevice(parseIntOrZero(tracker.getSenderDevice()));
            tmp.setSenderJid(tracker.getSenderJid());
            tmp.setTs(tracker.getTs());
            for (final Key k : tracker.getKeys()) {
                tmp.addKey(k);
            }
            tmp.setPayload(tracker.getPayload());

            final XmppX3dhpqMessage incoming =
                    XmppX3dhpqMessage.fromExtension(account, account.getJid().asBareJid(), tmp);
            final XmppX3dhpqMessage.EncryptedKey k = incoming.findKeyForDevice(ownDeviceId);
            if (k == null || k.prekey == null) {
                return TrackerOutcome.NOT_DECRYPTABLE;
            }
            final PrekeyEnvelope env = new PrekeyEnvelope(
                    k.prekey.ephemeralPub, k.prekey.kemCiphertext, k.prekey.kemKeyId,
                    k.prekey.opkId, k.prekey.dcMarshal, k.prekey.aikEd25519Pub,
                    k.prekey.aikMldsaPub);
            final Session session =
                    acceptInboundSessionAsSession(account.getJid().asBareJid(), ownDeviceId, env);
            final byte[] plaintext = incoming.decrypt(session, k);
            onDeviceTrackerDecrypted(plaintext);
            return TrackerOutcome.AUTHORIZED;
        } catch (final Exception e) {
            Log.d(Config.LOGTAG, LOGPREFIX + ": devtracker own-copy decrypt failed (§11.8): "
                    + e.getMessage());
            return TrackerOutcome.NOT_DECRYPTABLE;
        }
    }

    private static int parseIntOrZero(final String s) {
        try {
            return s == null ? 0 : Integer.parseInt(s);
        } catch (final NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Best-effort fold-forward on a successfully decrypted tracker payload: logs the
     * asserted device set for diagnostics, and — §11.8 "self-refreshing, device-key-sealed
     * recovery" — adopts the embedded AIK_priv ONLY in the defensive case where this
     * (already-authorized) device somehow has no local AIK row at all. Never overwrites an
     * existing row; never merges co-account device rows (that stays gated behind the
     * audit-chain trust check in {@link #handleInboundDeviceList}, §10.6.3).
     */
    private void onDeviceTrackerDecrypted(final byte[] plaintext) {
        if (db == null || account == null) {
            return;
        }
        try {
            final DecodedTracker decoded = parseDeviceTrackerPlaintextPayload(plaintext);
            final int deviceCount = decoded.snapshot != null ? decoded.snapshot.devices.size() : 0;
            Log.d(Config.LOGTAG, LOGPREFIX + ": devtracker decrypted — " + deviceCount
                    + " authorized device(s), "
                    + (decoded.heads != null ? decoded.heads.size() : 0) + " DAG head(s) (§11.8)");
            if (decoded.aikPriv != null) {
                final DatabaseBackend.X3dhpqAccountIdentityRow existing =
                        db.loadX3dhpqAccountIdentity(account.getUuid());
                if (existing == null) {
                    final String fp = decoded.aikPriv.getPublic().fingerprint(X3dhpqCrypto.BLAKE2B_160);
                    db.putX3dhpqAccountIdentity(account.getUuid(),
                            decoded.aikPriv.marshal(), decoded.aikPriv.getPublic().marshal(), fp);
                    Log.i(Config.LOGTAG, LOGPREFIX + ": adopted AIK_priv recovered from the"
                            + " sealed device-state tracker (§11.8)");
                }
            }
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": onDeviceTrackerDecrypted failed to parse payload"
                    + " (non-fatal, §11.8): " + e.getMessage());
        }
    }

    private void setTrackerRevokedFlag(final boolean revoked) {
        if (mXmppConnectionService == null || account == null) {
            return;
        }
        final android.content.SharedPreferences prefs =
                androidx.preference.PreferenceManager.getDefaultSharedPreferences(
                        mXmppConnectionService);
        prefs.edit()
                .putBoolean("x3dhpq_devtracker_revoked_" + account.getUuid(), revoked)
                .apply();
    }

    /**
     * §11.8: true once this (previously-authorized) device observed a validly-signed
     * sealed tracker whose own {@code &lt;key&gt;} copy it could not decrypt — the offline
     * revocation signal. Consumed by the device-management UI ({@code
     * X3dhpqSelfDevicesActivity}) to surface the same associate-or-reset choice normally
     * shown only for §10.6.1 pending enrollment. Cleared automatically the next time this
     * device is seen decrypting the tracker again (e.g. after being re-added).
     */
    public boolean isDisabledByTrackerRevocation() {
        if (mXmppConnectionService == null || account == null) {
            return false;
        }
        final android.content.SharedPreferences prefs =
                androidx.preference.PreferenceManager.getDefaultSharedPreferences(
                        mXmppConnectionService);
        return prefs.getBoolean("x3dhpq_devtracker_revoked_" + account.getUuid(), false);
    }

    /**
     * Revokes one of the account's own devices (§8.6). Authors a DIK-signed REMOVE
     * TrustEntry into the account Trust Manifest (the LIVE trust source), deletes the
     * device's local key material and republishes the signed devicelist with the device
     * omitted and the version bumped (the authoritative removal — item ③ machinery).
     * Peers and co-account devices tear down state for the vanished device on observing
     * the version-advanced list (handled inbound by {@link #handleInboundDeviceList} +
     * the remote-device prune).
     */
    public void revokeOwnDevice(final int deviceId) {
        if (db == null || account == null || mXmppConnectionService == null) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": revokeOwnDevice ignored — no db/account/service");
            return;
        }
        // HARD GUARD: never revoke the device we are running on — self-revoke
        // tombstones the account's own root and orphans the identity. Removing
        // THIS device is what "Account reset" (generate new identity) is for.
        final Integer ownId = getOwnDeviceIdOrNull();
        if (ownId != null && ownId == deviceId) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": REFUSING to revoke this device (" + Integer.toUnsignedString(deviceId)
                    + ") — self-revoke orphans the account; use Account reset instead");
            return;
        }
        // Task #54: revoke authorship is gated on TRUST (this device is in the manifest
        // fold), NOT on holding AIK_priv. With share_primary gone, any folded device can
        // author a DIK-signed REMOVE (confirmerRemoveDevice signs under the local DIK).
        if (!localDeviceCanAuthorTrust()) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": revokeOwnDevice ignored — this device is not a"
                    + " trusted member of the account (not in the manifest fold)");
            return;
        }
        final String accountUuid = account.getUuid();

        // Trust Manifest Phase 2 (§D4): the manifest is the LIVE trust source, so a revoke
        // MUST be a DIK-signed REMOVE TrustEntry — otherwise the revoked device stays in
        // the fold and keeps receiving messages. Author + publish the REMOVE (it also
        // applies the new fold locally, pruning the device from the trust tables the
        // fanout reads). Removal-wins is enforced by TrustManifest.fold().
        final boolean removed = confirmerRemoveDevice(deviceId);

        // 1. Drop this install's own key material for the device (if any lived here) and
        //    its co-account row — the manifest REMOVE handles trust, but the local key
        //    row must go too. The REMOVE fold above already pruned remote/co-account, so
        //    these deletes are belt-and-suspenders for the local-key case.
        db.deleteX3dhpqLocalDevice(accountUuid, deviceId);
        db.deleteX3dhpqCoAccountDevice(accountUuid, deviceId);

        // 2. Keep the devicelist as a derived cache (= fold output) so bundles/groups/UI
        //    keep working (§F). Name deviceId as an explicitly allowed removal so the
        //    shrink guard permits dropping exactly this id.
        publishDeviceList(java.util.Set.of(deviceId));

        if (!removed) {
            Log.w(Config.LOGTAG, LOGPREFIX + ": revokeOwnDevice("
                    + Integer.toUnsignedString(deviceId)
                    + ") published no manifest REMOVE (no manifest / target not in fold);"
                    + " derived devicelist cache still republished");
        }
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
        new X3dhpqSecurityNotifier(mXmppConnectionService)
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
        // Task #55: drop the manifest-state row for this peer too, so their post-reset
        // FRESH genesis (version=1 under the NEW AIK) is pinned + accepted as a new lineage
        // baseline rather than being compared against the old lineage's last-seen version.
        db.deleteX3dhpqManifestState(accountUuid, peer);
        Log.i(Config.LOGTAG, LOGPREFIX + ": " + peer
                + " explicitly re-trusted (§10.6.5) — TOFU pin reset, requesting fresh devicelist");
        requestPeerDeviceList(peerBareJid);
    }

    // Public so the pairing-complete handler can publish a freshly-paired
    // secondary's bundle immediately (see PairToExistingActivity). Per-device and
    // idempotent (PEP item id = deviceId), so it never affects other devices.
    public void publishOwnBundle() {
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
     * §11.8 "Queued enrollment request": explicitly fetches our own {@code pair-hello}
     * item on every connect, rather than relying solely on live self-PEP {@code
     * +notify}. A disabled device's request is published once and persists on the
     * server (whitelist, {@code persist_items=true}); an authorized device that was
     * offline at publish time would otherwise never learn about it until the disabled
     * device happens to be online again at the exact same moment. Routes the fetched
     * item through the same {@link #handleEvent} path a live event uses, so it both
     * (a) drives the pairing FSM immediately if the pairing screen happens to be open,
     * and (b) persists the "A new device wants to join your account" banner state via
     * {@link VerifyDeviceManager#handlePairHello} regardless.
     */
    public void fetchPairHelloOnConnect() {
        if (db == null || account == null || mXmppConnectionService == null) {
            return;
        }
        final Jid ownBareJid = account.getJid().asBareJid();
        final Iq iq = mXmppConnectionService.getIqGenerator().generateX3dhpqRequestPairHello(ownBareJid);
        mXmppConnectionService.sendIqPacket(account, iq, response -> {
            try {
                if (response.getType() != Iq.Type.RESULT) {
                    return;
                }
                final PubSub pubsub = response.getExtension(PubSub.class);
                final Items items = pubsub != null ? pubsub.getItems() : null;
                final var entry = items != null
                        ? items.getFirstItemWithId(
                                im.conversations.android.xmpp.model.x3dhpq.pair.PairHello.class)
                        : null;
                if (entry != null) {
                    handleEvent(ownBareJid, Namespace.X3DHPQ_PAIR, entry.getKey(), entry.getValue());
                }
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": fetchPairHelloOnConnect processing failed"
                        + " (non-fatal, §11.8/§10.1a): " + e.getMessage());
            }
        });
    }

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
         * True if this device is TRUSTED per the account Trust Manifest — i.e. it is the
         * account's primary (the genesis root of trust) or its device id is present in the
         * current manifest FOLD. False means it is present locally/on the devicelist but is
         * NOT (yet) in the account's trust manifest (e.g. a just-appeared device not yet
         * folded). This is derived from the fold, NOT the retired §11.4 audit chain.
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
    /**
     * Task #67: the set of device ids currently TRUSTED for the own account per the Trust
     * Manifest — i.e. the manifest FOLD membership. Uses the live fold of the current own
     * manifest when present; falls back to the committed device-id set (which {@code
     * writeFoldedTrustSet}/{@code publishDeviceList} persist = the fold/union output) for a
     * pre-migration account that has no manifest yet. Cosmetic read only — this does not
     * change trust, which is already driven by the fold.
     */
    private java.util.Set<Integer> foldedTrustedDeviceIds(
            final String accountUuid, final String ownBare) {
        final TrustManifest m = loadCurrentOwnManifest(accountUuid, ownBare);
        if (m != null) {
            try {
                final java.util.Set<Integer> ids = new java.util.HashSet<>();
                for (final Long id : TrustManifest.fold(m).keySet()) {
                    ids.add((int) (long) id);
                }
                return ids;
            } catch (final Exception e) {
                Log.w(Config.LOGTAG, LOGPREFIX + ": foldedTrustedDeviceIds fold failed, using"
                        + " committed set: " + e.getMessage());
            }
        }
        return db.loadX3dhpqCommittedDeviceIds(accountUuid);
    }

    public List<AssociatedDevice> listAssociatedDevices() {
        final List<AssociatedDevice> result = new ArrayList<>();
        if (db == null || account == null || isPendingEnrollment()) {
            return result;
        }
        final Integer ownDeviceId = getOwnDeviceIdOrNull();
        // Trust Manifest Phase 2 (task #67): a device is Confirmed iff it is in the current
        // manifest FOLD (the retired account-audit chain no longer participates in trust).
        // Reading the fold is cosmetic only; trust itself is already the fold.
        final java.util.Set<Integer> folded =
                foldedTrustedDeviceIds(account.getUuid(), account.getJid().asBareJid().toString());
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
            final boolean confirmed = primary || folded.contains(row.deviceId());
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
            final boolean confirmed = primary || folded.contains(row.deviceId());
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
            // Skip a device whose bundle DC permanently fails AIK verification (dead/forked,
            // never re-paired). It can never be encrypted to; treating it as a transient
            // "bundle missing" would fail-close the whole message and strand every recipient.
            // A not-yet-fetched bundle is different and still defers (below).
            if (dcInvalidDevices.contains(target + "/" + devId)) {
                Log.w(Config.LOGTAG,
                        "x3dhpq: skipping recipient " + target + "/" + devId
                                + " — DC does not verify against account AIK (revoke this device)");
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
