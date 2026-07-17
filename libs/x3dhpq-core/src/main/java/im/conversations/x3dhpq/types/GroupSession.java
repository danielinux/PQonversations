// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Per-room group session state (in-memory only; no wire serialisation in B3).
// Mirrors GroupSession from groupsession.go.
public final class GroupSession {

    public final String roomJID;
    public final AccountIdentityPub myAik;
    public final int myDeviceId;

    // Current epoch; incremented on every member add/remove.
    public int epoch;

    public final List<GroupMember> members = new ArrayList<>();
    public SenderChain sendChain;
    public final Map<RecvKey, SenderChain> recvChains = new HashMap<>();
    // Maps AIK fingerprint → epoch at which the member was removed (for §13.9).
    public final Map<String, Integer> removedAiks = new HashMap<>();

    // Rolling checkpoint of our send chain that announceSenderChain() exports
    // INSTEAD of the live (latest) ratchet position. A member that lacks a recv
    // chain (new device, was offline) can therefore only decrypt back to the
    // checkpoint, not to the epoch start. maybeAdvanceCheckpoint() slides it
    // forward at most once per max-age window (24h, set by the caller), so the
    // window of past messages exposed by re-sharing — the option-1 forward-
    // secrecy cost — is bounded to ~24h instead of the whole (possibly unbounded)
    // epoch. sendCkptKey is the chainKey snapshot AT sendCkptIndex.
    private byte[] sendCkptKey = new byte[0];
    private int sendCkptIndex = 0;
    private long sendCkptTime = 0L;   // unix seconds; 0 = not yet initialised

    // Blake2b160 hasher injected once for fingerprint operations.
    private final Blake2b160 hasher;

    private GroupSession(String roomJID, AccountIdentityPub myAik, int myDeviceId,
                         Blake2b160 hasher, int epoch, SenderChain sendChain) {
        this.roomJID    = roomJID;
        this.myAik      = myAik;
        this.myDeviceId = myDeviceId;
        this.hasher     = hasher;
        this.epoch      = epoch;
        this.sendChain  = sendChain;
    }

    // Create a new GroupSession with epoch=0 and a freshly-randomised sendChain.
    public static GroupSession create(String roomJID, AccountIdentityPub myAik, int myDeviceId,
                                      List<GroupMember> members, Blake2b160 hasher,
                                      HmacSha256 mac) {
        byte[] ck = freshChainKey();
        SenderChain sc = new SenderChain(0, ck);
        GroupSession gs = new GroupSession(roomJID, myAik, myDeviceId, hasher, 0, sc);
        gs.members.addAll(members);
        gs.sendCkptKey   = Arrays.copyOf(sc.chainKey, 32);
        gs.sendCkptIndex = 0;
        gs.sendCkptTime  = 0L;
        return gs;
    }

    // Add a member; if they were previously removed, un-remove them.
    // Rotates epoch and generates a fresh sendChain.
    public void addMember(GroupMember member) {
        String fp = member.aik.fingerprint(hasher);
        removedAiks.remove(fp);
        members.add(member);
        rotateEpoch();
    }

    // Remove a member by AIK fingerprint; drop their recv chains; rotate epoch;
    // record removal in removedAiks paired with the new epoch.
    public void removeMember(String aikFp) {
        members.removeIf(m -> aikFp.equals(m.aik.fingerprint(hasher)));
        recvChains.keySet().removeIf(k -> aikFp.equals(k.aikFp()));
        rotateEpoch();
        removedAiks.put(aikFp, epoch);
    }

    // Slide the announce checkpoint forward to the CURRENT send position once the
    // max-age window has elapsed. {@code now} is unix seconds; {@code maxAgeSeconds}
    // bounds the re-shareable history / forward-secrecy window (e.g. 24h). The
    // first call in an epoch just stamps the start time (checkpoint stays at
    // index 0 so a member joining early in the epoch still gets it whole).
    // Returns true iff the checkpoint actually moved (so the caller can persist).
    public boolean maybeAdvanceCheckpoint(long now, long maxAgeSeconds) {
        if (sendChain == null) return false;
        if (sendCkptTime == 0L) {
            sendCkptTime = now;
            return false;
        }
        if (now - sendCkptTime >= maxAgeSeconds) {
            sendCkptKey   = Arrays.copyOf(sendChain.chainKey, 32);
            sendCkptIndex = sendChain.nextIndex;
            sendCkptTime  = now;
            return true;
        }
        return false;
    }

    // Build a SenderChainAnnouncement for our send chain. Exports the rolling
    // CHECKPOINT (bounded history) rather than the live position, so a member
    // lacking a recv chain can decrypt back only to the checkpoint (≤ max-age
    // old), not the whole epoch. Falls back to the live position for a session
    // that has no stored checkpoint key (defensive; create()/rotateEpoch() always
    // stamp one).
    public SenderChainAnnouncement announceSenderChain() {
        final byte[] ck;
        final long nextIndex;
        if (sendCkptKey != null && sendCkptKey.length == 32) {
            ck = Arrays.copyOf(sendCkptKey, 32);
            nextIndex = sendCkptIndex & 0xFFFFFFFFL;
        } else {
            ck = Arrays.copyOf(sendChain.chainKey, 32);
            nextIndex = sendChain.nextIndex & 0xFFFFFFFFL;
        }
        return new SenderChainAnnouncement(
                myAik,
                myDeviceId & 0xFFFFFFFFL,
                roomJID,
                epoch & 0xFFFFFFFFL,
                ck,
                nextIndex);
    }

    // Accept a SenderChainAnnouncement from a peer.
    // Rejects if: wrong room, sender is in removedAiks, or sender not a current member.
    // On success: installs the chain into recvChains.
    public void acceptSenderChain(SenderChainAnnouncement ann) {
        if (!ann.roomJID.equals(roomJID)) {
            throw new IllegalArgumentException("GroupSession: announcement room mismatch");
        }
        String fp = ann.senderAIKPub.fingerprint(hasher);
        if (removedAiks.containsKey(fp)) {
            throw new IllegalStateException("GroupSession: announcement from removed member " + fp);
        }
        boolean found = false;
        for (GroupMember m : members) {
            if (m.aik.equals(ann.senderAIKPub)) {
                found = true;
                break;
            }
        }
        if (!found) {
            throw new IllegalArgumentException("GroupSession: announcement from unknown sender " + fp);
        }
        SenderChain sc = new SenderChain((int) ann.epoch, ann.chainKey);
        sc.nextIndex = (int) ann.nextIndex;
        RecvKey key = new RecvKey(fp, (int) ann.senderDeviceId, (int) ann.epoch);
        // Install ONCE per (sender, device, epoch). Announcements now carry a
        // forward-MOVING checkpoint; overwriting a recv chain we already ratcheted
        // forward with a LATER checkpoint would skip us past (and permanently lose)
        // messages between our position and the new checkpoint. A member that
        // already holds a chain for this epoch simply ratchets it forward / catches
        // up via MAM instead of re-installing.
        if (!recvChains.containsKey(key)) {
            recvChains.put(key, sc);
        }
    }

    // Rotate epoch: increment, generate a new random sendChain for the new epoch.
    private void rotateEpoch() {
        epoch++;
        sendChain = new SenderChain(epoch, freshChainKey());
        // Fresh epoch → the checkpoint restarts at the new chain's index 0, so
        // early members of the new epoch still get it whole; it then slides
        // forward again via maybeAdvanceCheckpoint.
        sendCkptKey   = Arrays.copyOf(sendChain.chainKey, 32);
        sendCkptIndex = 0;
        sendCkptTime  = 0L;
    }

    private static byte[] freshChainKey() {
        byte[] ck = new byte[32];
        new SecureRandom().nextBytes(ck);
        return ck;
    }
}
