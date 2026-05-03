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

    // Build a SenderChainAnnouncement for the current sendChain.
    public SenderChainAnnouncement announceSenderChain() {
        byte[] ck = Arrays.copyOf(sendChain.chainKey, 32);
        return new SenderChainAnnouncement(
                myAik,
                myDeviceId & 0xFFFFFFFFL,
                roomJID,
                epoch & 0xFFFFFFFFL,
                ck,
                sendChain.nextIndex & 0xFFFFFFFFL);
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
        recvChains.put(key, sc);
    }

    // Rotate epoch: increment, generate a new random sendChain for the new epoch.
    private void rotateEpoch() {
        epoch++;
        sendChain = new SenderChain(epoch, freshChainKey());
    }

    private static byte[] freshChainKey() {
        byte[] ck = new byte[32];
        new SecureRandom().nextBytes(ck);
        return ck;
    }
}
