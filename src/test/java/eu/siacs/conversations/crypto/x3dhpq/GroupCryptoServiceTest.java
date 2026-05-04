// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import im.conversations.x3dhpq.crypto.BouncyCastleInstaller;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.protocol.GroupEnvelope;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.GroupMember;
import im.conversations.x3dhpq.types.GroupMessageHeader;
import im.conversations.x3dhpq.types.GroupSession;
import im.conversations.x3dhpq.types.SenderChain;
import im.conversations.x3dhpq.types.SenderChainAnnouncement;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit tests for group crypto primitives used by GroupCryptoService.
 * Tests the crypto layer without requiring Android / DB scaffolding.
 */
public class GroupCryptoServiceTest {

    @BeforeClass
    public static void setUp() {
        BouncyCastleInstaller.ensureRegistered();
    }

    private static AccountIdentityPub makeAik(byte fill) {
        byte[] ed = new byte[32];   Arrays.fill(ed,    fill);
        byte[] ml = new byte[1952]; Arrays.fill(ml, (byte)(fill ^ 0x5A));
        return new AccountIdentityPub(ed, ml);
    }

    // -------------------------------------------------------------------------
    // GroupEnvelope encrypt/decrypt round-trip (pure crypto layer)
    // -------------------------------------------------------------------------

    @Test
    public void encryptDecrypt_groupMessage_roundTrip() {
        final String roomJid = "testroom@muc.example.org";
        final long epoch = 0L;
        final long deviceId = 7L;

        byte[] chainKey = new byte[32];
        Arrays.fill(chainKey, (byte) 0x42);
        SenderChain sc = new SenderChain(0, chainKey);

        int idx = sc.nextIndex;
        byte[] mk = sc.step(X3dhpqCrypto.HMAC_SHA256);

        GroupMessageHeader hdr = new GroupMessageHeader(epoch, deviceId, idx);
        byte[] nonce = GroupMessageHeader.aeadNonce(epoch, idx);
        byte[] aad   = hdr.aad(roomJid);

        byte[] plaintext = "wave E group message".getBytes(StandardCharsets.UTF_8);
        byte[] ct = X3dhpqCrypto.aes256gcmEncrypt(mk, nonce, plaintext, aad);

        GroupEnvelope env = new GroupEnvelope(hdr, ct);

        // "Transport" via XML: marshal → wire bytes → unmarshal
        byte[] wireHdr = env.marshalHeader();
        byte[] wireCt  = env.getCiphertext();
        GroupEnvelope received = GroupEnvelope.unmarshal(wireHdr, wireCt);

        // Receiver chain: same chainKey, step to same index
        SenderChain rxChain = new SenderChain(0, Arrays.copyOf(chainKey, 32));
        byte[] rxMk = rxChain.step(X3dhpqCrypto.HMAC_SHA256);

        byte[] rxNonce = GroupMessageHeader.aeadNonce(received.header.epoch, received.header.chainIndex);
        byte[] rxAad   = received.header.aad(roomJid);
        byte[] decrypted = X3dhpqCrypto.aes256gcmDecrypt(rxMk, rxNonce, received.ciphertext, rxAad);

        Assert.assertArrayEquals("Group decrypt must recover original plaintext", plaintext, decrypted);
    }

    // -------------------------------------------------------------------------
    // GroupSession + SenderChain: encrypt then re-install chain and decrypt
    // -------------------------------------------------------------------------

    @Test
    public void groupSession_announceAndAccept_thenDecrypt() {
        final String roomJid = "multiroom@conference.example.org";

        AccountIdentityPub aliceAik = makeAik((byte) 0x01);
        AccountIdentityPub bobAik   = makeAik((byte) 0x02);

        GroupMember alice = new GroupMember(aliceAik, List.of(1));
        GroupMember bob   = new GroupMember(bobAik,   List.of(2));

        // Alice's session
        GroupSession aliceSes = GroupSession.create(
                roomJid, aliceAik, 1, List.of(bob),
                X3dhpqCrypto.BLAKE2B_160, X3dhpqCrypto.HMAC_SHA256);

        // Alice announces her sender chain to Bob
        SenderChainAnnouncement ann = aliceSes.announceSenderChain();
        Assert.assertEquals(roomJid, ann.roomJID);
        Assert.assertEquals(0L, ann.epoch);

        // Bob's session
        GroupSession bobSes = GroupSession.create(
                roomJid, bobAik, 2, List.of(alice),
                X3dhpqCrypto.BLAKE2B_160, X3dhpqCrypto.HMAC_SHA256);

        // Bob installs Alice's chain
        bobSes.acceptSenderChain(ann);

        // Alice encrypts a message
        int txIdx = aliceSes.sendChain.nextIndex;
        byte[] txMk = aliceSes.sendChain.step(X3dhpqCrypto.HMAC_SHA256);
        GroupMessageHeader txHdr = new GroupMessageHeader(0L, 1L, txIdx);
        byte[] txNonce = GroupMessageHeader.aeadNonce(0L, txIdx);
        byte[] txAad   = txHdr.aad(roomJid);
        byte[] plaintext = "alice says hi".getBytes(StandardCharsets.UTF_8);
        byte[] ct = X3dhpqCrypto.aes256gcmEncrypt(txMk, txNonce, plaintext, txAad);

        // Build GroupEnvelope
        GroupEnvelope env = new GroupEnvelope(txHdr, ct);
        byte[] wireHdr = env.marshalHeader();
        byte[] wireCt  = env.getCiphertext();

        // Bob decrypts
        GroupEnvelope rxEnv = GroupEnvelope.unmarshal(wireHdr, wireCt);
        String aliceFp = aliceAik.fingerprint(X3dhpqCrypto.BLAKE2B_160);
        im.conversations.x3dhpq.types.RecvKey rk = new im.conversations.x3dhpq.types.RecvKey(
                aliceFp, 1, (int) rxEnv.header.epoch);
        SenderChain rxChain = bobSes.recvChains.get(rk);
        Assert.assertNotNull("Bob must have installed Alice's recv chain", rxChain);

        byte[] rxMk = rxChain.step(X3dhpqCrypto.HMAC_SHA256);
        byte[] rxNonce   = GroupMessageHeader.aeadNonce(rxEnv.header.epoch, rxEnv.header.chainIndex);
        byte[] rxAad     = rxEnv.header.aad(roomJid);
        byte[] decrypted = X3dhpqCrypto.aes256gcmDecrypt(rxMk, rxNonce, rxEnv.ciphertext, rxAad);

        Assert.assertArrayEquals("Bob must decrypt Alice's group message", plaintext, decrypted);
    }

    // -------------------------------------------------------------------------
    // Epoch rotation after AddMember
    // -------------------------------------------------------------------------

    @Test
    public void addMember_rotatesEpochAndRefreshesSendChain() {
        AccountIdentityPub myAik   = makeAik((byte) 0x01);
        AccountIdentityPub peerAik = makeAik((byte) 0x02);

        GroupSession gs = GroupSession.create(
                "room@muc.example", myAik, 1, new ArrayList<>(),
                X3dhpqCrypto.BLAKE2B_160, X3dhpqCrypto.HMAC_SHA256);
        Assert.assertEquals(0, gs.epoch);
        byte[] oldCk = Arrays.copyOf(gs.sendChain.chainKey, 32);

        gs.addMember(new GroupMember(peerAik, List.of(7)));
        Assert.assertEquals("epoch must increment on addMember", 1, gs.epoch);
        Assert.assertFalse("sendChain must be refreshed after epoch rotation",
                Arrays.equals(oldCk, gs.sendChain.chainKey));
    }

    // -------------------------------------------------------------------------
    // SenderChainAnnouncement marshal round-trip
    // -------------------------------------------------------------------------

    @Test
    public void senderChainAnnouncement_marshalRoundTrip() {
        AccountIdentityPub aik = makeAik((byte) 0x03);
        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0x77);
        SenderChainAnnouncement ann = new SenderChainAnnouncement(
                aik, 99L, "room@muc.example", 2L, ck, 5L);

        byte[] wire = ann.marshal();
        SenderChainAnnouncement ann2 = SenderChainAnnouncement.unmarshal(wire);

        Assert.assertEquals("room@muc.example", ann2.roomJID);
        Assert.assertEquals(99L,  ann2.senderDeviceId);
        Assert.assertEquals(2L,   ann2.epoch);
        Assert.assertEquals(5L,   ann2.nextIndex);
        Assert.assertArrayEquals(ck, ann2.chainKey);
    }
}
