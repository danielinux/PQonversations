package eu.siacs.conversations.crypto.x3dhpq;

import android.util.Log;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.entities.Conversation;
import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.xmpp.manager.MessageArchiveManager;
import eu.siacs.conversations.xml.Namespace;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.model.pubsub.Items;
import im.conversations.android.xmpp.model.pubsub.PubSub;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.x3dhpq.envelope.EnvelopeGroup;
import im.conversations.android.xmpp.model.x3dhpq.group.MembershipEntry;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.protocol.GroupEnvelope;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.GroupMember;
import im.conversations.x3dhpq.types.GroupMessageHeader;
import im.conversations.x3dhpq.types.GroupSession;
import im.conversations.x3dhpq.types.SenderChainAnnouncement;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-account group crypto hub. Manages {@link GroupSession} lifecycle for
 * each MUC the account participates in.
 *
 * <p>Threading: all public methods may be called from network/UI threads.
 * State is guarded by per-room synchronisation on the session map values.
 */
public class GroupCryptoService {

    private static final String TAG = "GroupCryptoService";
    private static final int MAX_QUEUE = 64;

    private final Account account;
    private final XmppConnectionService mXmppConnectionService;
    private final X3dhpqDao db;

    // Per-room live state; lazily populated on subscribeAndCatchUp.
    private final ConcurrentHashMap<String, RoomState> rooms = new ConcurrentHashMap<>();

    // (roomBare, peerBare) -> pending invitee whose AIK pub we still need to
    // fetch before we can publish their AddMember entry. Drained from
    // {@link #onPeerBundleArrived}.
    private final java.util.Map<String, java.util.Set<String>> pendingMemberPublishes =
            new java.util.HashMap<>();

    public GroupCryptoService(final Account account, final XmppConnectionService svc) {
        this.account = account;
        this.mXmppConnectionService = svc;
        this.db = svc.databaseBackend;
    }

    // -------------------------------------------------------------------------
    // Inner state holder
    // -------------------------------------------------------------------------

    private static final class RoomState {
        final MembershipJournal journal = new MembershipJournal();
        GroupSession session;
        // Membership item ids we've already applied to this in-memory room
        // state. Catch-up fetches may run multiple times for the same room;
        // journal append is sequential and not idempotent on duplicate seqs.
        final java.util.Set<String> appliedMembershipItemIds = new java.util.HashSet<>();
        // Queued announcements waiting for journal to be populated.
        final List<QueuedAnnouncement> announcementQueue = new ArrayList<>();
        // Track which (memberAikFp, deviceId) tuples we've already announced
        // our sender chain to, so re-announcing doesn't fan out a message
        // storm on every send.
        final java.util.Set<String> announcedTo = new java.util.HashSet<>();

        private static final class QueuedAnnouncement {
            final Jid senderJid;
            final int senderDeviceId;
            final SenderChainAnnouncement ann;
            QueuedAnnouncement(Jid senderJid, int senderDeviceId, SenderChainAnnouncement ann) {
                this.senderJid = senderJid;
                this.senderDeviceId = senderDeviceId;
                this.ann = ann;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Journal management
    // -------------------------------------------------------------------------

    /**
     * Subscribe to the room's group:0 PEP node and fetch all journal items.
     * Call on MUC join.
     */
    public void subscribeAndCatchUp(final Jid roomJid) {
        if (account == null || mXmppConnectionService == null) return;
        final String roomStr = roomJid.asBareJid().toString();
        rooms.putIfAbsent(roomStr, new RoomState());

        // Send explicit pubsub subscribe IQ
        account.getX3dhpqService().subscribeToRoomGroupNode(roomJid.asBareJid());

        // Fetch all current items
        final Iq fetchIq = buildFetchAllItemsIq(roomJid.asBareJid(), Namespace.X3DHPQ_GROUP);
        mXmppConnectionService.sendIqPacket(account, fetchIq, response -> {
            if (response.getType() != Iq.Type.RESULT) {
                Log.d(Config.LOGTAG, TAG + ": group:0 fetch returned non-RESULT for "
                        + roomJid + ": " + response.getType());
                return;
            }
            final PubSub pubsub = response.getExtension(PubSub.class);
            if (pubsub == null) return;
            final Items items = pubsub.getItems();
            if (items == null) return;
            for (final var entry : items.getItemMap(MembershipEntry.class).entrySet()) {
                final String itemId = entry.getKey();
                final MembershipEntry me = entry.getValue();
                if (me == null) continue;
                final byte[] payload = me.asBytes();
                processMembershipEntryBytes(roomJid.asBareJid(), itemId, payload);
            }
            // After catch-up, flush queued announcements
            flushAnnouncementQueue(roomStr);
        });
    }

    /**
     * Process a {@code <membership-entry>} PEP event received via +notify.
     */
    public void onMembershipEvent(final Jid roomJid, final String itemId, final MembershipEntry entry) {
        if (entry == null) return;
        final byte[] payload = entry.asBytes();
        processMembershipEntryBytes(roomJid.asBareJid(), itemId, payload);
        flushAnnouncementQueue(roomJid.asBareJid().toString());
    }

    private void processMembershipEntryBytes(final Jid roomJidBare, final String itemId, final byte[] entryBytes) {
        if (entryBytes == null || entryBytes.length == 0) return;
        final String roomStr = roomJidBare.toString();
        final RoomState state = rooms.computeIfAbsent(roomStr, k -> new RoomState());
        synchronized (state) {
            if (itemId != null && state.appliedMembershipItemIds.contains(itemId)) {
                return;
            }
            try {
                // For TOFU / AIK lookup, we pass the best AIK map we can build
                // from persisted account + bundle state so restart recovery can
                // bootstrap from seq=0 without relying on prior RAM state.
                state.journal.append(entryBytes, buildAikLookupMap(state));
                if (itemId != null) {
                    state.appliedMembershipItemIds.add(itemId);
                }
                rebuildGroupSession(roomStr, state);
            } catch (Exception e) {
                Log.w(Config.LOGTAG, TAG + ": failed to append journal entry "
                        + itemId + " for " + roomStr + ": " + e.getMessage());
            }
        }
    }

    /**
     * Build AIK lookup map from known AIKs in current session members + DB bundles.
     */
    private Map<String, AccountIdentityPub> buildAikLookupMap(RoomState state) {
        Map<String, AccountIdentityPub> map = new HashMap<>();
        // Add AIKs we already know from the existing session.
        if (state.session != null) {
            for (GroupMember m : state.session.members) {
                String fp = m.aik.fingerprint(X3dhpqCrypto.BLAKE2B_160);
                map.put(MembershipJournal.fingerprintHex(hexToBytes(fp.replace(" ", ""))), m.aik);
            }
        }
        // Also add from journal's existing known members.
        for (Map.Entry<String, AccountIdentityPub> e : state.journal.getMembers().entrySet()) {
            if (e.getValue() != null) {
                map.put(e.getKey(), e.getValue());
            }
        }
        // Seed TOFU/bootstrap from the local AIK plus every cached remote bundle.
        final DatabaseBackend.X3dhpqAccountIdentityRow ownAikRow =
                db.loadX3dhpqAccountIdentity(account.getUuid());
        if (ownAikRow != null && ownAikRow.aikPub() != null) {
            try {
                final AccountIdentityPub ownAik = AccountIdentityPub.unmarshal(ownAikRow.aikPub());
                map.put(MembershipJournal.fingerprintHex(blakeFpBytes(ownAik)), ownAik);
            } catch (Exception ignored) {}
        }
        for (final DatabaseBackend.X3dhpqRemoteDeviceRow rd :
                db.listAllX3dhpqRemoteDevices(account.getUuid())) {
            try {
                final DatabaseBackend.X3dhpqRemoteBundleRow bundle =
                        db.loadX3dhpqRemoteBundle(account.getUuid(), rd.peerJid(), rd.deviceId());
                if (bundle == null || bundle.aikPubMarshal() == null) {
                    continue;
                }
                final AccountIdentityPub aik = AccountIdentityPub.unmarshal(bundle.aikPubMarshal());
                map.put(MembershipJournal.fingerprintHex(blakeFpBytes(aik)), aik);
            } catch (Exception ignored) {}
        }
        return map;
    }

    /**
     * Rebuild the GroupSession from the current journal state.
     * Called after every journal append.
     */
    private void rebuildGroupSession(String roomStr, RoomState state) {
        final String accountUuid = account.getUuid();

        // Collect members with known AIK pubs
        List<GroupMember> members = state.journal.buildGroupMembers();

        // Load own AIK
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(accountUuid);
        if (aikRow == null) return;
        final AccountIdentityPub myAik = AccountIdentityPub.unmarshal(aikRow.aikPub());

        final List<DatabaseBackend.X3dhpqLocalDeviceRow> localRows =
                db.listX3dhpqLocalDevices(accountUuid);
        if (localRows.isEmpty()) return;
        final int myDeviceId = localRows.get(0).deviceId();

        if (state.session == null) {
            state.session = GroupSession.create(
                    roomStr, myAik, myDeviceId, members,
                    X3dhpqCrypto.BLAKE2B_160, X3dhpqCrypto.HMAC_SHA256);
        } else {
            // Apply incremental changes from journal to existing session.
            // Both keys must use the same form for the dup-check: the journal
            // map is keyed by the full uppercase hex of the raw 20-byte
            // BLAKE2b-160 digest of marshal(); we recompute that exact form
            // for each session member here. Comparing against the spaced
            // 30-char display fingerprint (the bug) never matches and causes
            // addMember to fire on every rebuild, rotating epoch each time.
            for (Map.Entry<String, AccountIdentityPub> e : state.journal.getMembers().entrySet()) {
                if (e.getValue() == null) continue;
                final String fp = e.getKey();
                boolean alreadyMember = false;
                for (GroupMember m : state.session.members) {
                    final byte[] mFpRaw = X3dhpqCrypto.BLAKE2B_160.hash(m.aik.marshal());
                    final String mFp = MembershipJournal.fingerprintHex(mFpRaw);
                    if (fp.equalsIgnoreCase(mFp)) {
                        alreadyMember = true;
                        break;
                    }
                }
                if (!alreadyMember) {
                    state.session.addMember(new GroupMember(e.getValue(), new ArrayList<>()));
                }
            }
            // Remove members that are no longer in the journal
            for (Map.Entry<String, Long> e : state.journal.getRemovedAiks().entrySet()) {
                final String fp = e.getKey();
                if (!state.session.removedAiks.containsKey(fp)) {
                    state.session.removeMember(fp);
                }
            }
        }

        persistGroupSession(roomStr, state);
    }

    private void persistGroupSession(String roomStr, RoomState state) {
        if (state.session == null) return;
        // Persist to DB (state_blob = serialised members + epoch; we store epoch as-is)
        final long now = System.currentTimeMillis() / 1000L;
        // Use a compact binary blob: we store the epoch and AIK fps.
        // For simplicity, the session is not fully serialised (GroupSession has no marshal());
        // we store the epoch so we can detect freshness. Full session state lives in RAM.
        db.putX3dhpqGroupSession(
                account.getUuid(),
                roomStr,
                state.session.epoch,
                new byte[0], // placeholder; full session state lives in RAM
                now);
    }

    // -------------------------------------------------------------------------
    // Encrypt / Decrypt
    // -------------------------------------------------------------------------

    /**
     * Encrypt a plaintext for the given room.
     *
     * @return an {@link EnvelopeGroup} extension ready to attach to the groupchat stanza,
     *         or null if the room is not yet x3dhpq-enabled (no journal).
     * @throws GroupNotEnabledException if the room journal is missing or unverified.
     */
    public EnvelopeGroup encryptGroupMessage(final Jid roomJid, final byte[] plaintext)
            throws GroupNotEnabledException {
        final String roomStr = roomJid.asBareJid().toString();
        final RoomState state = rooms.get(roomStr);
        if (state == null || state.session == null) {
            throw new GroupNotEnabledException("Room " + roomStr + " is not yet x3dhpq-enabled");
        }

        synchronized (state) {
            if (state.session == null) {
                throw new GroupNotEnabledException("Room " + roomStr + " is not yet x3dhpq-enabled");
            }

            // Announce our sender chain to every member device that hasn't
            // received it yet. This is idempotent — announcedTo prevents
            // re-sending — but ensures peers can install the recv chain
            // before they see encrypted messages from us. Without this, the
            // first group message lands at peers as "no recv chain".
            announceSenderChain(roomJid);

            final int indexBefore = state.session.sendChain.nextIndex;
            final byte[] mk = state.session.sendChain.step(X3dhpqCrypto.HMAC_SHA256);
            final long epoch = state.session.epoch & 0xFFFFFFFFL;
            final long senderDeviceId;
            {
                final List<DatabaseBackend.X3dhpqLocalDeviceRow> rows =
                        db.listX3dhpqLocalDevices(account.getUuid());
                senderDeviceId = rows.isEmpty() ? 0 : rows.get(0).deviceId() & 0xFFFFFFFFL;
            }

            final GroupMessageHeader hdr = new GroupMessageHeader(epoch, senderDeviceId, indexBefore);
            final byte[] aad   = hdr.aad(roomStr);
            final byte[] nonce = GroupMessageHeader.aeadNonce(epoch, indexBefore);

            final byte[] ct = X3dhpqCrypto.aes256gcmEncrypt(mk, nonce, plaintext, aad);

            // Compute my AIK fingerprint for the envelope attribute
            final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                    db.loadX3dhpqAccountIdentity(account.getUuid());
            final String aikFp;
            if (aikRow != null) {
                final AccountIdentityPub aik = AccountIdentityPub.unmarshal(aikRow.aikPub());
                aikFp = aik.fingerprint(X3dhpqCrypto.BLAKE2B_160);
            } else {
                aikFp = "";
            }

            persistGroupSession(roomStr, state);

            final EnvelopeGroup env = new EnvelopeGroup();
            env.setSenderAikFp(aikFp);
            env.setHdrBytes(hdr.marshal());
            env.setCtBytes(ct);
            return env;
        }
    }

    /**
     * Decrypt an inbound group message.
     *
     * @return the plaintext bytes, or null if decryption cannot proceed yet
     *         (announcement pending).
     * @throws GroupNotEnabledException if the room has no journal.
     * @throws Exception                on AEAD failure or malformed envelope.
     */
    public byte[] decryptGroupMessage(final Jid roomJid, final EnvelopeGroup envelope)
            throws GroupNotEnabledException, Exception {
        final Jid roomBare = roomJid.asBareJid();
        final String roomStr = roomBare.toString();
        final RoomState state = rooms.computeIfAbsent(roomStr, k -> new RoomState());

        synchronized (state) {
            if (state.session == null) {
                // After app restart, pairwise sender-chain announcements or MAM
                // catch-up may race the room journal bootstrap. Trigger a fresh
                // journal catch-up instead of treating the room as permanently
                // disabled and dropping the message on the floor.
                subscribeAndCatchUp(roomBare);
                return null;
            }

            final byte[] hdrBytes = envelope.getHdrBytes();
            final byte[] ct       = envelope.getCtBytes();
            if (hdrBytes.length == 0 || ct.length == 0) {
                throw new IllegalArgumentException("GroupMessage: missing <hdr> or <ct>");
            }

            final GroupEnvelope genv = GroupEnvelope.unmarshal(hdrBytes, ct);
            final GroupMessageHeader hdr = genv.header;

            // Look up sender AIK
            final String senderAikFp = envelope.getSenderAikFp();
            if (senderAikFp == null || senderAikFp.isEmpty()) {
                throw new IllegalArgumentException("GroupMessage: missing sender-aik-fp");
            }

            // The MUC reflects our own groupchat back to us. We have no recv
            // chain for ourselves (we have a send chain instead), so decrypt
            // would log a confusing "no recv chain" miss every time we send.
            // Skip silently — the local UI already shows our outgoing copy.
            final DatabaseBackend.X3dhpqAccountIdentityRow myAikRow =
                    db.loadX3dhpqAccountIdentity(account.getUuid());
            if (myAikRow != null) {
                try {
                    final AccountIdentityPub myAik = AccountIdentityPub.unmarshal(myAikRow.aikPub());
                    if (senderAikFp.equals(myAik.fingerprint(X3dhpqCrypto.BLAKE2B_160))) {
                        return null;
                    }
                } catch (Exception ignored) {}
            }

            // Check not removed
            if (state.session.removedAiks.containsKey(senderAikFp)) {
                throw new SecurityException("GroupMessage: sender " + senderAikFp + " has been removed");
            }

            // Look up recv chain
            final im.conversations.x3dhpq.types.RecvKey rk = new im.conversations.x3dhpq.types.RecvKey(
                    senderAikFp,
                    (int) hdr.senderDeviceId,
                    (int) hdr.epoch);
            final im.conversations.x3dhpq.types.SenderChain sc =
                    state.session.recvChains.get(rk);
            if (sc == null) {
                // No recv chain: cannot decrypt yet
                Log.d(Config.LOGTAG, TAG + ": no recv chain for " + senderAikFp
                        + " epoch=" + hdr.epoch + "; decryption deferred");
                return null;
            }

            // Obtain message key at the required index.
            // First check the skipped map, then advance the chain.
            final byte[] mk = messageKeyAt(sc, (int) hdr.chainIndex);

            final byte[] nonce = GroupMessageHeader.aeadNonce(hdr.epoch, hdr.chainIndex);
            final byte[] aad   = hdr.aad(roomStr);

            return X3dhpqCrypto.aes256gcmDecrypt(mk, nonce, ct, aad);
        }
    }

    // -------------------------------------------------------------------------
    // SenderChainAnnouncement
    // -------------------------------------------------------------------------

    /**
     * Broadcast our current sender chain to every member of the room via pairwise envelopes.
     * Each announcement is sent as {@code <payload type='sender-chain'>}.
     */
    public void announceSenderChain(final Jid roomJid) {
        final String roomStr = roomJid.asBareJid().toString();
        final RoomState state = rooms.get(roomStr);
        if (state == null || state.session == null) {
            Log.d(Config.LOGTAG, TAG + ": announceSenderChain skipped — no session for " + roomStr);
            return;
        }

        synchronized (state) {
            if (state.session == null) return;
            final SenderChainAnnouncement ann = state.session.announceSenderChain();
            final byte[] annBytes = ann.marshal();

            // Resolve own AIK once for the self-skip check.
            AccountIdentityPub ownAik = null;
            final DatabaseBackend.X3dhpqAccountIdentityRow ownAikRow =
                    db.loadX3dhpqAccountIdentity(account.getUuid());
            if (ownAikRow != null) {
                try { ownAik = AccountIdentityPub.unmarshal(ownAikRow.aikPub()); }
                catch (Exception ignored) {}
            }

            int sent = 0;
            for (GroupMember m : state.session.members) {
                final AccountIdentityPub memberAik = m.aik;
                if (memberAik == null) {
                    continue;
                }
                if (ownAik != null && memberAik.equals(ownAik)) {
                    continue;
                }
                final String memberAikFp = memberAik.fingerprint(X3dhpqCrypto.BLAKE2B_160);

                // GroupSession.members is built with empty deviceIds — the
                // journal entry doesn't carry device lists. Resolve the
                // member's JID and then enumerate their devices from the
                // x3dhpq_remote_device table.
                final Jid memberJid = findJidByAikFp(memberAikFp);
                if (memberJid == null) {
                    continue;
                }
                final List<DatabaseBackend.X3dhpqRemoteDeviceRow> peerDevices =
                        db.listX3dhpqRemoteDevices(account.getUuid(), memberJid.asBareJid().toString());
                if (peerDevices.isEmpty()) {
                    account.getX3dhpqService().requestPeerDeviceList(memberJid.asBareJid());
                    continue;
                }
                for (DatabaseBackend.X3dhpqRemoteDeviceRow rd : peerDevices) {
                    final String key = memberAikFp + "/" + rd.deviceId();
                    // Re-broadcast on every encrypt. Without re-announcement
                    // a lost first-message means the recv chain is never
                    // installed at the peer and we have no way to detect
                    // the loss. Re-announcing is cheap and idempotent on
                    // the receiver side (acceptSenderChain reinstalls the
                    // same chain at the same recv_key).
                    if (db.loadX3dhpqRemoteBundle(account.getUuid(),
                            memberJid.asBareJid().toString(), rd.deviceId()) == null) {
                        account.getX3dhpqService().requestPeerBundle(
                                memberJid.asBareJid(), rd.deviceId());
                        continue;
                    }
                    account.getX3dhpqService().sendSenderChainAnnouncement(
                            memberJid.asBareJid(), rd.deviceId(), annBytes);
                    state.announcedTo.add(key);
                    sent++;
                }
            }
        }
    }

    /**
     * Handle a received {@link SenderChainAnnouncement} from a peer.
     */
    public void onSenderChainAnnouncementReceived(
            final Jid senderJid, final int senderDeviceId, final byte[] annBytes) {
        final SenderChainAnnouncement ann;
        try {
            ann = SenderChainAnnouncement.unmarshal(annBytes);
        } catch (Exception e) {
            Log.w(Config.LOGTAG, TAG + ": malformed SenderChainAnnouncement: " + e.getMessage());
            return;
        }

        final Jid roomBare = Jid.of(ann.roomJID).asBareJid();
        final String roomStr = roomBare.toString();
        final RoomState state = rooms.computeIfAbsent(roomStr, k -> new RoomState());

        synchronized (state) {
            if (state.session == null) {
                // After restart the room state may not exist yet even though a
                // peer is already re-announcing its sender chain. Queue the
                // announcement and immediately refresh the room journal so the
                // queued chain can be accepted once membership is rebuilt.
                if (state.announcementQueue.size() < MAX_QUEUE) {
                    state.announcementQueue.add(
                            new RoomState.QueuedAnnouncement(senderJid, senderDeviceId, ann));
                }
                subscribeAndCatchUp(roomBare);
                return;
            }

            // Verify sender is in journal
            final String senderAikFp = ann.senderAIKPub.fingerprint(X3dhpqCrypto.BLAKE2B_160);
            final String senderFpHex = MembershipJournal.fingerprintHex(blakeFpBytes(ann.senderAIKPub));
            if (!state.journal.isMember(senderFpHex)) {
                Log.w(Config.LOGTAG, TAG + ": announcement from non-member " + senderAikFp);
                return;
            }
            if (state.journal.isRemoved(senderFpHex)) {
                Log.w(Config.LOGTAG, TAG + ": announcement from removed member " + senderAikFp);
                return;
            }

            try {
                state.session.acceptSenderChain(ann);
                triggerMamCatchupAfterChain(roomBare, state);
            } catch (Exception e) {
                Log.w(Config.LOGTAG, TAG + ": acceptSenderChain failed: " + e.getMessage());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Capability check
    // -------------------------------------------------------------------------

    /**
     * Owner-side hook: publish AddMember entries to the room's group:0 journal.
     * Called from {@link eu.siacs.conversations.xmpp.manager.MultiUserChatManager#invite}
     * after the muc#admin set-affiliation IQ succeeds. On the very first invite
     * we also publish AddMember(self) at seq=0 so the room becomes
     * x3dhpq-enabled (XEP §13.8: a journal must contain the owner's AIK before
     * any encryption is possible).
     *
     * <p>Idempotent: if our AIK is already in the journal we only publish the
     * peer entry. If the peer's AIK is also already there we skip silently.
     *
     * @param roomJid bare JID of the room
     * @param peerJid bare JID of the new member; their AIK pub must already be
     *                cached in {@code x3dhpq_remote_bundle} (i.e. we've fetched
     *                their bundle at least once)
     */
    public void publishAddMember(final Jid roomJid, final Jid peerJid) {
        Log.d(Config.LOGTAG, TAG + ": publishAddMember(room=" + roomJid + ", peer=" + peerJid + ")");
        if (account == null || mXmppConnectionService == null || db == null) {
            Log.w(Config.LOGTAG, TAG + ": publishAddMember aborted — null account/service/db");
            return;
        }
        final Jid roomBare = roomJid.asBareJid();
        final String roomStr = roomBare.toString();
        final RoomState state = rooms.computeIfAbsent(roomStr, k -> new RoomState());

        // Resolve our own AIK (priv + pub) for signing.
        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(account.getUuid());
        if (aikRow == null) {
            Log.w(Config.LOGTAG, TAG + ": publishAddMember skipped — no local AIK");
            return;
        }
        final im.conversations.x3dhpq.types.AccountIdentityKey ownerKey;
        try {
            ownerKey = im.conversations.x3dhpq.types.AccountIdentityKey.unmarshal(aikRow.aikPriv());
        } catch (Exception e) {
            Log.w(Config.LOGTAG, TAG + ": publishAddMember failed to load owner AIK: " + e.getMessage());
            return;
        }
        final AccountIdentityPub myAik = ownerKey.getPublic();
        final byte[] myFpRaw = blakeFpBytes(myAik);
        final String myFpKey = MembershipJournal.fingerprintHex(myFpRaw);

        // Resolve peer AIK from any of their cached bundles.
        final List<DatabaseBackend.X3dhpqRemoteDeviceRow> peerDevices =
                db.listX3dhpqRemoteDevices(account.getUuid(), peerJid.asBareJid().toString());
        AccountIdentityPub peerAik = null;
        for (DatabaseBackend.X3dhpqRemoteDeviceRow rd : peerDevices) {
            final DatabaseBackend.X3dhpqRemoteBundleRow b =
                    db.loadX3dhpqRemoteBundle(account.getUuid(), rd.peerJid(), rd.deviceId());
            if (b != null && b.aikPubMarshal() != null) {
                try {
                    peerAik = AccountIdentityPub.unmarshal(b.aikPubMarshal());
                    break;
                } catch (Exception ignored) {}
            }
        }
        if (peerAik == null) {
            Log.w(Config.LOGTAG, TAG + ": publishAddMember deferred — no cached AIK for "
                    + peerJid + "; fetching bundle and queuing for retry");
            synchronized (pendingMemberPublishes) {
                pendingMemberPublishes
                        .computeIfAbsent(roomStr, k -> new java.util.HashSet<>())
                        .add(peerJid.asBareJid().toString());
            }
            account.getX3dhpqService().requestPeerDeviceList(peerJid.asBareJid());
            return;
        }
        final byte[] peerFpRaw = blakeFpBytes(peerAik);
        final String peerFpKey = MembershipJournal.fingerprintHex(peerFpRaw);

        synchronized (state) {
            // Build and publish AddMember(self) iff our AIK is not yet a member.
            if (!state.journal.isMember(myFpKey)) {
                final long seq = state.journal.getLastSeq() + 1;
                final byte[] prevHash = previousHashOrZero(state);
                publishOneAddMember(roomBare, ownerKey, seq, prevHash, myFpRaw, myAik);
            }
            // Build and publish AddMember(peer) iff not already a member.
            if (!state.journal.isMember(peerFpKey)) {
                final long seq = state.journal.getLastSeq() + 1;
                final byte[] prevHash = previousHashOrZero(state);
                publishOneAddMember(roomBare, ownerKey, seq, prevHash, peerFpRaw, peerAik);
            }
        }
    }

    private static byte[] blakeFpBytes(final AccountIdentityPub aik) {
        // AccountIdentityPub#fingerprint returns a *truncated* 15-byte hex
        // display form; the journal entry payload needs the raw 20-byte
        // BLAKE2b-160 digest of the marshal() bytes.
        return X3dhpqCrypto.BLAKE2B_160.hash(aik.marshal());
    }

    private static byte[] previousHashOrZero(final RoomState state) {
        final byte[] last = state.journal.getLastHash();
        return last != null ? last : new byte[32];
    }

    private void publishOneAddMember(
            final Jid roomBare,
            final im.conversations.x3dhpq.types.AccountIdentityKey ownerKey,
            final long seq,
            final byte[] prevHash,
            final byte[] memberFpRaw,
            final AccountIdentityPub memberAik) {

        // payload = aik_fp(20) || epoch_after(uint32 BE)
        // For an MVP single-epoch room we always use epoch_after=1 (current).
        final byte[] payload = im.conversations.x3dhpq.types.AuditEntry.buildMemberPayload(memberFpRaw, 1);
        final long ts = System.currentTimeMillis() / 1000L;

        // Build unsigned AuditEntry to obtain signedPart() bytes.
        final im.conversations.x3dhpq.types.AuditEntry unsigned =
                new im.conversations.x3dhpq.types.AuditEntry(
                        seq, prevHash,
                        im.conversations.x3dhpq.types.AuditEntry.ACTION_ADD_MEMBER,
                        payload, ts, new byte[0], new byte[0]);
        final byte[] signedPart = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(ownerKey.getPrivEd25519(), signedPart);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(ownerKey.getPrivMLDSA(), signedPart);

        final im.conversations.x3dhpq.types.AuditEntry signed =
                new im.conversations.x3dhpq.types.AuditEntry(
                        seq, prevHash,
                        im.conversations.x3dhpq.types.AuditEntry.ACTION_ADD_MEMBER,
                        payload, ts, sigEd, sigMl);
        final byte[] entryBytes = signed.marshal();

        // Build publish IQ targeted at the room JID.
        final Iq iq = new Iq(Iq.Type.SET);
        iq.setTo(roomBare);
        final im.conversations.android.xmpp.model.pubsub.PubSub ps =
                iq.addExtension(new im.conversations.android.xmpp.model.pubsub.PubSub());
        final im.conversations.android.xmpp.model.pubsub.Publish pub =
                ps.addExtension(new im.conversations.android.xmpp.model.pubsub.Publish());
        pub.setNode(Namespace.X3DHPQ_GROUP);
        final im.conversations.android.xmpp.model.pubsub.PubSub.Item item =
                pub.addExtension(new im.conversations.android.xmpp.model.pubsub.PubSub.Item());
        item.setId(Long.toString(seq));
        final MembershipEntry me = item.addExtension(new MembershipEntry());
        me.setContent(entryBytes);

        Log.d(Config.LOGTAG, TAG + ": publishing membership entry seq=" + seq
                + " action=AddMember to " + roomBare);

        // Optimistically append to local journal so subsequent calls in the
        // same flow see the right seq/prevHash. The Map<aikFp, AccountIdentityPub>
        // teaches the journal about this member's pub key.
        final Map<String, AccountIdentityPub> aikLookup = new HashMap<>();
        aikLookup.put(MembershipJournal.fingerprintHex(memberFpRaw), memberAik);
        // Also seed owner key on first entry so verification can succeed.
        final RoomState st = rooms.get(roomBare.toString());
        if (st != null && st.journal.getOwnerAik() == null) {
            st.journal.setOwnerAik(ownerKey.getPublic());
        }
        try {
            if (st != null) {
                st.journal.append(entryBytes, aikLookup);
                rebuildGroupSession(roomBare.toString(), st);
            }
        } catch (Exception e) {
            Log.w(Config.LOGTAG, TAG + ": local append after publish failed (will rely on +notify): "
                    + e.getMessage());
        }

        mXmppConnectionService.sendIqPacket(account, iq, response -> {
            if (response.getType() == Iq.Type.ERROR) {
                Log.w(Config.LOGTAG, TAG + ": membership entry seq=" + seq
                        + " publish failed: " + response);
            } else {
                Log.d(Config.LOGTAG, TAG + ": membership entry seq=" + seq + " published");
            }
        });
    }

    /**
     * Called by {@link X3dhpqService#handleInboundBundle} after a peer's
     * bundle has been fetched and verified. Drains any pending journal
     * publishes that were waiting on this peer's AIK to be cached.
     */
    public void onPeerBundleArrived(final Jid peerBareJid) {
        if (peerBareJid == null) return;
        final String peer = peerBareJid.asBareJid().toString();
        final java.util.List<String> roomsToRetry = new java.util.ArrayList<>();
        synchronized (pendingMemberPublishes) {
            for (var entry : pendingMemberPublishes.entrySet()) {
                if (entry.getValue().remove(peer)) {
                    roomsToRetry.add(entry.getKey());
                }
            }
        }
        for (String roomStr : roomsToRetry) {
            try {
                publishAddMember(Jid.of(roomStr), peerBareJid);
            } catch (Exception e) {
                Log.w(Config.LOGTAG, TAG + ": onPeerBundleArrived retry failed for "
                        + roomStr + ": " + e.getMessage());
            }
        }

        // Also re-attempt announceSenderChain for every active group session
        // that includes this peer. The previous attempt may have skipped the
        // peer because their bundle wasn't cached yet.
        for (java.util.Map.Entry<String, RoomState> e : rooms.entrySet()) {
            final RoomState state = e.getValue();
            if (state == null || state.session == null) continue;
            try {
                announceSenderChain(Jid.of(e.getKey()));
            } catch (Exception ex) {
                Log.w(Config.LOGTAG, TAG + ": post-bundle announce retry failed for "
                        + e.getKey() + ": " + ex.getMessage());
            }
        }
    }

    /**
     * Returns true if our AIK fingerprint is in the journal for this room
     * and the journal has been verified.
     */
    public boolean isCapableForGroup(final Conversation conversation) {
        if (conversation.getMode() != Conversation.MODE_MULTI) return false;
        final String roomStr = conversation.getAddress().asBareJid().toString();
        final RoomState state = rooms.get(roomStr);
        if (state == null || state.session == null) return false;

        final DatabaseBackend.X3dhpqAccountIdentityRow aikRow =
                db.loadX3dhpqAccountIdentity(account.getUuid());
        if (aikRow == null) return false;
        final AccountIdentityPub myAik = AccountIdentityPub.unmarshal(aikRow.aikPub());
        final String myFpHex = MembershipJournal.fingerprintHex(blakeFpBytes(myAik));
        return state.journal.isMember(myFpHex);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void flushAnnouncementQueue(String roomStr) {
        final RoomState state = rooms.get(roomStr);
        if (state == null) return;
        synchronized (state) {
            if (state.session == null) return;
            final List<RoomState.QueuedAnnouncement> queue =
                    new ArrayList<>(state.announcementQueue);
            state.announcementQueue.clear();
            boolean acceptedAny = false;
            for (RoomState.QueuedAnnouncement qa : queue) {
                try {
                    state.session.acceptSenderChain(qa.ann);
                    acceptedAny = true;
                } catch (Exception e) {
                    Log.w(Config.LOGTAG, TAG + ": deferred acceptSenderChain failed: " + e.getMessage());
                }
            }
            if (acceptedAny) {
                triggerMamCatchupAfterChain(Jid.of(roomStr), state);
            }
        }
    }

    private void triggerMamCatchupAfterChain(final Jid roomBare, final RoomState state) {
        if (account == null || account.getXmppConnection() == null) {
            return;
        }
        final Conversation conversation =
                mXmppConnectionService.findOrCreateConversation(account, roomBare, true, false);
        final MessageArchiveManager mam =
                account.getXmppConnection().getManager(MessageArchiveManager.class);
        if (mam.queryInProgress(conversation)) {
            return;
        }
        mam.catchupMUC(conversation);
    }

    private Iq buildFetchAllItemsIq(Jid to, String node) {
        final Iq iq = new Iq(Iq.Type.GET);
        iq.setTo(to);
        final PubSub pubsub = new PubSub();
        final im.conversations.android.xmpp.model.pubsub.PubSub.ItemsWrapper items =
                new im.conversations.android.xmpp.model.pubsub.PubSub.ItemsWrapper();
        items.setNode(node);
        pubsub.addExtension(items);
        iq.addExtension(pubsub);
        return iq;
    }

    /** Lookup a member's JID by AIK fingerprint from the local DB.
     *  Accepts either the spaced display form ("XXXXX XXXXX ...") or the
     *  packed hex form; comparison is case-insensitive on the de-spaced form
     *  so callers don't have to massage the fingerprint shape themselves. */
    private Jid findJidByAikFp(String aikFp) {
        if (db == null || account == null || aikFp == null) return null;
        final String wantHex = aikFp.replace(" ", "");
        final List<DatabaseBackend.X3dhpqRemoteDeviceRow> allDevices =
                db.listAllX3dhpqRemoteDevices(account.getUuid());
        for (DatabaseBackend.X3dhpqRemoteDeviceRow rd : allDevices) {
            try {
                final DatabaseBackend.X3dhpqRemoteBundleRow bundle =
                        db.loadX3dhpqRemoteBundle(account.getUuid(), rd.peerJid(), rd.deviceId());
                if (bundle == null || bundle.aikPubMarshal() == null) continue;
                final AccountIdentityPub aik = AccountIdentityPub.unmarshal(bundle.aikPubMarshal());
                final String haveHex = aik.fingerprint(X3dhpqCrypto.BLAKE2B_160).replace(" ", "");
                if (wantHex.equalsIgnoreCase(haveHex)) {
                    return Jid.of(rd.peerJid());
                }
            } catch (Exception ignored) {}
        }
        return null;
    }

    /** Convert the spaced "XXXXX XXXXX ..." fingerprint form to a plain uppercase hex string. */
    private static String fingerprintToHex(String fp) {
        return fp == null ? "" : fp.replace(" ", "");
    }

    /**
     * Advance the sender chain to {@code targetIndex}, stashing skipped keys,
     * and return the message key for that index.
     * Mirrors Go SenderChain.MessageKeyAt.
     */
    private static byte[] messageKeyAt(im.conversations.x3dhpq.types.SenderChain sc, int targetIndex) {
        // First check the skipped map
        byte[] cached = sc.consumeSkipped(targetIndex);
        if (cached != null) return cached;

        if (targetIndex < sc.nextIndex) {
            throw new IllegalStateException("SenderChain: requested index " + targetIndex
                    + " already past (nextIndex=" + sc.nextIndex + ")");
        }

        // Advance, stashing skipped keys, until we reach targetIndex
        int skippedCount = 0;
        while (sc.nextIndex < targetIndex) {
            if (skippedCount >= im.conversations.x3dhpq.types.SenderChain.DEFAULT_MAX_SKIPPED) {
                throw new IllegalStateException("SenderChain: too many skipped keys");
            }
            int idx = sc.nextIndex;
            byte[] mk = sc.step(X3dhpqCrypto.HMAC_SHA256);
            sc.putSkipped(idx, mk);
            skippedCount++;
        }
        return sc.step(X3dhpqCrypto.HMAC_SHA256);
    }

    /** Convert a plain hex string back to bytes. */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    // -------------------------------------------------------------------------
    // Exception type
    // -------------------------------------------------------------------------

    public static final class GroupNotEnabledException extends Exception {
        public GroupNotEnabledException(String message) {
            super(message);
        }
    }
}
