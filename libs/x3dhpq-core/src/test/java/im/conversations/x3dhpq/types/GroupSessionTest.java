// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;

class GroupSessionTest {

    private static final InlineBlake2b160 HASHER = new InlineBlake2b160();
    private static final HmacSha256       MAC    = new BcHmacSha256();

    private static AccountIdentityPub buildAik(byte fill) {
        byte[] pubEd = new byte[32];
        Arrays.fill(pubEd, fill);
        byte[] pubMLDSA = new byte[1952];
        Arrays.fill(pubMLDSA, (byte) (fill ^ 0x5A));
        return new AccountIdentityPub(pubEd, pubMLDSA);
    }

    @Test
    void createSessionHasEpochZero() {
        AccountIdentityPub myAik = buildAik((byte) 0x01);
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 1, List.of(), HASHER, MAC);
        Assertions.assertEquals(0, gs.epoch, "initial epoch must be 0");
    }

    @Test
    void addMemberRotatesEpoch() {
        AccountIdentityPub myAik = buildAik((byte) 0x01);
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 1, List.of(), HASHER, MAC);
        AccountIdentityPub peerAik = buildAik((byte) 0x02);
        GroupMember peer = new GroupMember(peerAik, List.of(42));
        gs.addMember(peer);
        Assertions.assertEquals(1, gs.epoch, "epoch must be 1 after addMember");
        Assertions.assertEquals(1, gs.members.size(), "member list must have 1 entry");
    }

    @Test
    void removeMemberRecordsInRemovedAiks() {
        AccountIdentityPub myAik = buildAik((byte) 0x01);
        AccountIdentityPub peerAik = buildAik((byte) 0x02);
        GroupMember peer = new GroupMember(peerAik, List.of(42));
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 1, List.of(peer), HASHER, MAC);
        String fp = peerAik.fingerprint(HASHER);
        gs.removeMember(fp);
        Assertions.assertTrue(gs.removedAiks.containsKey(fp),
                "removeMember must record AIK fp in removedAiks");
        Assertions.assertEquals(1, gs.epoch, "epoch must be 1 after removeMember");
        Assertions.assertEquals(0, gs.members.size(), "member list must be empty after remove");
    }

    @Test
    void acceptSenderChainRejectsUnknownAik() {
        AccountIdentityPub myAik = buildAik((byte) 0x01);
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 1, List.of(), HASHER, MAC);

        AccountIdentityPub unknownAik = buildAik((byte) 0x99);
        byte[] ck = new byte[32];
        SenderChainAnnouncement ann = new SenderChainAnnouncement(
                unknownAik, 99L, "room@conf.example", 0L, ck, 0L);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> gs.acceptSenderChain(ann), "unknown AIK must be rejected");
    }

    @Test
    void acceptSenderChainRejectsRemovedAik() {
        AccountIdentityPub myAik  = buildAik((byte) 0x01);
        AccountIdentityPub peer   = buildAik((byte) 0x02);
        GroupMember m = new GroupMember(peer, List.of(7));
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 1, List.of(m), HASHER, MAC);
        String fp = peer.fingerprint(HASHER);
        gs.removeMember(fp);

        byte[] ck = new byte[32];
        SenderChainAnnouncement ann = new SenderChainAnnouncement(
                peer, 7L, "room@conf.example", 0L, ck, 0L);
        Assertions.assertThrows(IllegalStateException.class,
                () -> gs.acceptSenderChain(ann), "removed AIK must be rejected");
    }

    @Test
    void acceptSenderChainRejectsWrongRoom() {
        AccountIdentityPub myAik  = buildAik((byte) 0x01);
        AccountIdentityPub peer   = buildAik((byte) 0x02);
        GroupMember m = new GroupMember(peer, List.of(7));
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 1, List.of(m), HASHER, MAC);

        byte[] ck = new byte[32];
        SenderChainAnnouncement ann = new SenderChainAnnouncement(
                peer, 7L, "other@conf.example", 0L, ck, 0L);
        Assertions.assertThrows(IllegalArgumentException.class,
                () -> gs.acceptSenderChain(ann), "wrong room must be rejected");
    }

    @Test
    void acceptSenderChainInstallsRecvChain() {
        AccountIdentityPub myAik  = buildAik((byte) 0x01);
        AccountIdentityPub peer   = buildAik((byte) 0x02);
        GroupMember m = new GroupMember(peer, List.of(7));
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 1, List.of(m), HASHER, MAC);

        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0x33);
        SenderChainAnnouncement ann = new SenderChainAnnouncement(
                peer, 7L, "room@conf.example", 0L, ck, 0L);
        gs.acceptSenderChain(ann);
        Assertions.assertEquals(1, gs.recvChains.size(), "one recv chain must be installed");
    }

    @Test
    void announceSenderChainMatchesCurrentState() {
        AccountIdentityPub myAik = buildAik((byte) 0x01);
        GroupSession gs = GroupSession.create(
                "room@conf.example", myAik, 5, List.of(), HASHER, MAC);
        SenderChainAnnouncement ann = gs.announceSenderChain();
        Assertions.assertEquals("room@conf.example", ann.roomJID);
        Assertions.assertEquals(5L, ann.senderDeviceId);
        Assertions.assertEquals(0L, ann.epoch);
        Assertions.assertArrayEquals(gs.sendChain.chainKey, ann.chainKey);
    }
}
