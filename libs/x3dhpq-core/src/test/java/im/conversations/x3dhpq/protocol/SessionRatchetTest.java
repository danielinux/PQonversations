// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.BouncyCastleInstaller;
import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// Tests for the Triple Ratchet Session (D5).
// All crypto via BouncyCastle; no Android dependencies.
class SessionRatchetTest {

    // Shared PQXDH-derived keys used to seed both sessions in each test.
    private byte[] rootKey;
    private byte[] chainKey;
    private byte[] ad;

    // Alice is initiator (sender), Bob is responder (receiver).
    private Session alice;
    private Session bob;

    // Bob's initial DH keypair (plays the role of SPK in PQXDH).
    private KeyPair bobInitialDh;

    @BeforeAll
    static void setUpCrypto() {
        // Register BouncyCastle so AES/GCM and other JCE operations work in unit tests.
        BouncyCastleInstaller.ensureRegistered();
    }

    @BeforeEach
    void setUp() {
        // Synthesise a fake PQXDH output: random 32-byte rootKey, chainKey, 64-byte AD.
        rootKey  = X3dhpqCrypto.x25519GenerateKeypair().pub; // 32 random bytes
        chainKey = X3dhpqCrypto.x25519GenerateKeypair().pub; // 32 random bytes
        ad       = new byte[64];
        System.arraycopy(rootKey,  0, ad,  0, 32);
        System.arraycopy(chainKey, 0, ad, 32, 32);

        // Bob's initial DH keypair (the responder's "SPK" equivalent).
        bobInitialDh = X3dhpqCrypto.x25519GenerateKeypair();

        // Alice = INITIATOR: pre-ratchets using Bob's initial DH pub (mirrors NewSendingState).
        // The PQXDH initialChainKey is discarded (Go: _ = ck).
        PqxdhResult aliceRes = makePqxdhResult(PqxdhResult.Role.INITIATOR, rootKey, chainKey, ad);
        alice = Session.fromPqxdhSenderWithPeerDh(aliceRes, bobInitialDh.pub);

        // Bob = RESPONDER: recv chain = initialChainKey; sendDhPriv = bobInitialDh.priv (mirrors NewReceivingState).
        PqxdhResult bobRes = makePqxdhResult(PqxdhResult.Role.RESPONDER, rootKey, chainKey, ad);
        bob = Session.fromPqxdhReceiverWithDh(bobRes, bobInitialDh.priv, bobInitialDh.pub);
    }

    // -------------------------------------------------------------------------
    // Round-trip basic
    // -------------------------------------------------------------------------

    @Test
    void basicRoundTrip_aliceToBob() throws SessionException {
        // Alice sends; Bob decrypts.
        byte[] plain = "hello".getBytes(StandardCharsets.UTF_8);
        Session.EncryptResult enc = alice.encrypt(plain);
        byte[] decrypted = bob.decrypt(enc.header, enc.ciphertext);
        Assertions.assertArrayEquals(plain, decrypted, "Bob must decrypt Alice's message");
    }

    @Test
    void basicRoundTrip_bobToAlice() throws SessionException {
        // Alice must first receive a message from Bob (or send one) to establish remoteDhPub.
        // Bootstrap: Alice sends first to seed Bob's remoteDhPub; then Bob replies.
        Session.EncryptResult aliceMsg = alice.encrypt("ping".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(aliceMsg.header, aliceMsg.ciphertext);

        byte[] plain = "world".getBytes(StandardCharsets.UTF_8);
        Session.EncryptResult enc = bob.encrypt(plain);
        byte[] decrypted = alice.decrypt(enc.header, enc.ciphertext);
        Assertions.assertArrayEquals(plain, decrypted, "Alice must decrypt Bob's reply");
    }

    @Test
    void multipleRoundTrips() throws SessionException {
        // 5 messages each direction.
        for (int i = 0; i < 5; i++) {
            String msg = "alice-" + i;
            Session.EncryptResult enc = alice.encrypt(msg.getBytes(StandardCharsets.UTF_8));
            byte[] dec = bob.decrypt(enc.header, enc.ciphertext);
            Assertions.assertArrayEquals(msg.getBytes(StandardCharsets.UTF_8), dec);
        }

        // Bob replies; but first he needs to have received at least one message (done above).
        for (int i = 0; i < 5; i++) {
            String msg = "bob-" + i;
            Session.EncryptResult enc = bob.encrypt(msg.getBytes(StandardCharsets.UTF_8));
            byte[] dec = alice.decrypt(enc.header, enc.ciphertext);
            Assertions.assertArrayEquals(msg.getBytes(StandardCharsets.UTF_8), dec);
        }
    }

    // -------------------------------------------------------------------------
    // Out-of-order delivery
    // -------------------------------------------------------------------------

    @Test
    void outOfOrderDelivery() throws SessionException {
        // Alice sends 5 messages.
        Session.EncryptResult[] encs = new Session.EncryptResult[5];
        for (int i = 0; i < 5; i++) {
            encs[i] = alice.encrypt(("msg-" + i).getBytes(StandardCharsets.UTF_8));
        }

        // Bob receives in order: 2, 0, 1, 4, 3.
        int[] order = {2, 0, 1, 4, 3};
        for (int idx : order) {
            byte[] dec = bob.decrypt(encs[idx].header, encs[idx].ciphertext);
            Assertions.assertArrayEquals(("msg-" + idx).getBytes(StandardCharsets.UTF_8), dec,
                    "out-of-order message " + idx + " must decrypt correctly");
        }
    }

    // -------------------------------------------------------------------------
    // Skipped key bound
    // -------------------------------------------------------------------------

    @Test
    void skippedKeyBoundExceeded_throws() {
        // Alice sends MAX_SKIPPED+2 messages; Bob tries to decrypt only the last one,
        // requiring MAX_SKIPPED+1 skips → must throw.
        int count = Session.MAX_SKIPPED + 2;
        Session.EncryptResult[] encs = new Session.EncryptResult[count];
        for (int i = 0; i < count; i++) {
            encs[i] = alice.encrypt(("m" + i).getBytes(StandardCharsets.UTF_8));
        }
        // Bob tries to skip MAX_SKIPPED+1 keys at once → must throw.
        Assertions.assertThrows(SessionException.class,
                () -> bob.decrypt(encs[count - 1].header, encs[count - 1].ciphertext),
                "skipping more than MAX_SKIPPED must throw");
    }

    // -------------------------------------------------------------------------
    // DH ratchet step
    // -------------------------------------------------------------------------

    @Test
    void dhRatchetStep_rootKeyAdvances() throws SessionException {
        // Capture Alice's root key before Bob replies.
        byte[] rkBefore = alice.getRootKey();

        // Alice sends, Bob decrypts (triggers Bob's DH ratchet on recv).
        Session.EncryptResult aliceMsg = alice.encrypt("step1".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(aliceMsg.header, aliceMsg.ciphertext);

        // Bob replies (triggers Alice's DH ratchet on recv).
        Session.EncryptResult bobMsg = bob.encrypt("step2".getBytes(StandardCharsets.UTF_8));
        alice.decrypt(bobMsg.header, bobMsg.ciphertext);

        // Root key must have changed on Alice after the DH ratchet.
        byte[] rkAfter = alice.getRootKey();
        Assertions.assertFalse(Arrays.equals(rkBefore, rkAfter),
                "root key must advance after DH ratchet step");
    }

    @Test
    void dhRatchetStep_newEphemeralInHeader() throws SessionException {
        // Alice's first message carries her sendDhPub.
        byte[] aliceDhBefore = alice.getSendDhPub();

        Session.EncryptResult enc1 = alice.encrypt("hello".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(enc1.header, enc1.ciphertext);

        // Bob sends a reply; his header carries his ephemeral.
        Session.EncryptResult bobMsg = bob.encrypt("reply".getBytes(StandardCharsets.UTF_8));
        alice.decrypt(bobMsg.header, bobMsg.ciphertext);

        // Alice's next encrypt should use a new DH pub (ratcheted after seeing Bob's).
        Session.EncryptResult enc2 = alice.encrypt("after-ratchet".getBytes(StandardCharsets.UTF_8));

        // Alice's DH pub must have changed after she saw Bob's ephemeral.
        Assertions.assertFalse(Arrays.equals(aliceDhBefore, enc2.header.dhPub),
                "Alice must use a new ephemeral DH after ratchet");
    }

    // -------------------------------------------------------------------------
    // KEM checkpoint at message 50
    // -------------------------------------------------------------------------

    @Test
    void kemCheckpoint_at50Messages_flagSet() throws SessionException {
        // KEM checkpoints require both sides to have exchanged KEM pubs first.
        KemKeyPair aliceKem = X3dhpqCrypto.mlkem768GenerateKeypair();
        KemKeyPair bobKem   = X3dhpqCrypto.mlkem768GenerateKeypair();

        alice.setKemRecvKeyPair(aliceKem.priv, aliceKem.pub);
        bob.setKemRecvKeyPair(bobKem.priv, bobKem.pub);

        // Bootstrap: Alice sends, Bob decrypts (Bob learns aliceKem.pub from header).
        // Bob replies, Alice decrypts (Alice learns bobKem.pub from header).
        Session.EncryptResult bootAlice = alice.encrypt("boot".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(bootAlice.header, bootAlice.ciphertext);
        Session.EncryptResult bootBob = bob.encrypt("reply".getBytes(StandardCharsets.UTF_8));
        alice.decrypt(bootBob.header, bootBob.ciphertext);

        // Alice now has kemSendPub = bobKem.pub.
        // kemSinceCheckpoint after bootAlice = 1. Send 49 more to bring it to 50.
        // Then the next (51st total) message triggers the checkpoint.
        for (int i = 0; i < 49; i++) {
            Session.EncryptResult enc = alice.encrypt(("m" + i).getBytes(StandardCharsets.UTF_8));
            Assertions.assertFalse(enc.header.hasKemCheckpoint(),
                    "message " + i + " must NOT have a checkpoint (i=" + i + ")");
            bob.decrypt(enc.header, enc.ciphertext);
        }

        // 51st Alice message (kemSinceCheckpoint==50 at entry → checkpoint fires).
        Session.EncryptResult checkpointMsg = alice.encrypt("checkpoint".getBytes(StandardCharsets.UTF_8));
        Assertions.assertTrue(checkpointMsg.header.hasKemCheckpoint(),
                "message at kemSinceCheckpoint=50 must carry a KEM checkpoint");
    }

    @Test
    void kemCheckpoint_decryptSucceedsAfterCheckpoint() throws SessionException {
        KemKeyPair aliceKem = X3dhpqCrypto.mlkem768GenerateKeypair();
        KemKeyPair bobKem   = X3dhpqCrypto.mlkem768GenerateKeypair();

        alice.setKemRecvKeyPair(aliceKem.priv, aliceKem.pub);
        bob.setKemRecvKeyPair(bobKem.priv, bobKem.pub);

        // Bootstrap exchange so both sides learn each other's KEM pub.
        Session.EncryptResult bootAlice = alice.encrypt("boot".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(bootAlice.header, bootAlice.ciphertext);
        Session.EncryptResult bootBob = bob.encrypt("reply".getBytes(StandardCharsets.UTF_8));
        alice.decrypt(bootBob.header, bootBob.ciphertext);

        // Send 49 more from Alice (boot already sent 1, so total = 50 before checkpoint).
        // Then send the checkpoint message (index 50).
        Session.EncryptResult[] encs = new Session.EncryptResult[49];
        for (int i = 0; i < 49; i++) {
            encs[i] = alice.encrypt(("m" + i).getBytes(StandardCharsets.UTF_8));
        }
        Session.EncryptResult checkpointEnc = alice.encrypt("ckpt".getBytes(StandardCharsets.UTF_8));
        Assertions.assertTrue(checkpointEnc.header.hasKemCheckpoint(),
                "checkpoint message must carry KEM ciphertext");

        // Bob decrypts all; checkpoint must be processed transparently.
        for (int i = 0; i < 49; i++) {
            byte[] dec = bob.decrypt(encs[i].header, encs[i].ciphertext);
            Assertions.assertArrayEquals(("m" + i).getBytes(StandardCharsets.UTF_8), dec,
                    "message " + i + " must decrypt correctly");
        }
        byte[] ckptDec = bob.decrypt(checkpointEnc.header, checkpointEnc.ciphertext);
        Assertions.assertArrayEquals("ckpt".getBytes(StandardCharsets.UTF_8), ckptDec,
                "checkpoint message must decrypt correctly");

        // Verify the checkpoint ciphertext was present.
        Assertions.assertTrue(checkpointEnc.header.hasKemCheckpoint(),
                "message at kemSinceCheckpoint=50 must carry KEM checkpoint ciphertext");
    }

    @Test
    void kemCheckpoint_kemHistoryUpdatesAndBothSidesAgree() throws SessionException {
        // Verify that after a KEM checkpoint:
        // 1. kemHistory on both sides is non-zero and identical.
        // 2. Post-checkpoint messages from Alice still decrypt correctly at Bob.
        KemKeyPair aliceKem = X3dhpqCrypto.mlkem768GenerateKeypair();
        KemKeyPair bobKem   = X3dhpqCrypto.mlkem768GenerateKeypair();

        alice.setKemRecvKeyPair(aliceKem.priv, aliceKem.pub);
        // Bob's KEM recv key; Alice will encapsulate to it on Alice's checkpoint.
        bob.setKemRecvKeyPair(bobKem.priv, bobKem.pub);
        // Alice's kemSendPub = Bob's KEM recv pub (Alice encapsulates to Bob's KEM pub).
        alice.setKemSendPub(bobKem.pub);

        // Bootstrap: Alice sends one message carrying her kemRecvPub in the header.
        // Bob learns aliceKem.pub from the header's kemPubForReply field.
        Session.EncryptResult bootAlice = alice.encrypt("boot".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(bootAlice.header, bootAlice.ciphertext);
        // After decrypt, bob.kemSendPub = aliceKem.pub (set from header.kemPubForReply).

        // Capture kemHistory before checkpoint.
        byte[] aliceHistoryBefore = alice.getKemHistory();

        // Alice sends 49 more messages + 1 checkpoint (total kemSinceCheckpoint = 51,
        // checkpoint fires at 50).  Bob decrypts all; Alice and Bob stay in same DH epoch.
        Session.EncryptResult[] encs = new Session.EncryptResult[49];
        for (int i = 0; i < 49; i++) {
            encs[i] = alice.encrypt(("m" + i).getBytes(StandardCharsets.UTF_8));
        }
        Session.EncryptResult checkpointEnc = alice.encrypt("ckpt".getBytes(StandardCharsets.UTF_8));
        Assertions.assertTrue(checkpointEnc.header.hasKemCheckpoint(),
                "50th message must carry KEM checkpoint");

        for (int i = 0; i < 49; i++) {
            bob.decrypt(encs[i].header, encs[i].ciphertext);
        }
        bob.decrypt(checkpointEnc.header, checkpointEnc.ciphertext);

        // kemHistory must have changed and be identical on both sides.
        byte[] aliceHistoryAfter = alice.getKemHistory();
        byte[] bobHistoryAfter   = bob.getKemHistory();
        Assertions.assertFalse(Arrays.equals(aliceHistoryBefore, aliceHistoryAfter),
                "kemHistory must change after KEM checkpoint");
        Assertions.assertArrayEquals(aliceHistoryAfter, bobHistoryAfter,
                "kemHistory must be identical on sender and receiver after checkpoint");

        // Post-checkpoint message from Alice decrypts correctly.
        Session.EncryptResult postCkpt = alice.encrypt("post".getBytes(StandardCharsets.UTF_8));
        byte[] postDec = bob.decrypt(postCkpt.header, postCkpt.ciphertext);
        Assertions.assertArrayEquals("post".getBytes(StandardCharsets.UTF_8), postDec,
                "post-checkpoint message must decrypt correctly");
    }

    // -------------------------------------------------------------------------
    // Tampered ciphertext
    // -------------------------------------------------------------------------

    @Test
    void tamperedCiphertext_throwsSessionException() {
        Session.EncryptResult enc = alice.encrypt("secret".getBytes(StandardCharsets.UTF_8));
        byte[] tampered = Arrays.copyOf(enc.ciphertext, enc.ciphertext.length);
        tampered[0] ^= 0xFF;
        Assertions.assertThrows(SessionException.class,
                () -> bob.decrypt(enc.header, tampered),
                "bit-flip in ciphertext must cause SessionException");
    }

    @Test
    void tamperedHeader_throwsSessionException() {
        Session.EncryptResult enc = alice.encrypt("secret".getBytes(StandardCharsets.UTF_8));
        // Tamper the header by faking a different N value.
        MessageHeader badHeader = new MessageHeader(
                enc.header.dhPub, enc.header.prevChainLen,
                enc.header.n + 1,   // wrong N → AAD mismatch
                enc.header.kemCiphertext, enc.header.kemPubForReply);
        Assertions.assertThrows(SessionException.class,
                () -> bob.decrypt(badHeader, enc.ciphertext),
                "tampered header must cause SessionException (AAD mismatch)");
    }

    // -------------------------------------------------------------------------
    // Marshal / unmarshal round-trip
    // -------------------------------------------------------------------------

    @Test
    void marshalUnmarshal_stateSurvives() throws SessionException {
        // Alice sends 3 messages; Bob decrypts 2.
        Session.EncryptResult enc0 = alice.encrypt("m0".getBytes(StandardCharsets.UTF_8));
        Session.EncryptResult enc1 = alice.encrypt("m1".getBytes(StandardCharsets.UTF_8));
        Session.EncryptResult enc2 = alice.encrypt("m2".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(enc0.header, enc0.ciphertext);
        bob.decrypt(enc1.header, enc1.ciphertext);

        // Serialise Bob's state, then restore.
        byte[] blob   = bob.marshal();
        Session bob2  = Session.unmarshal(blob);

        // Bob2 must decrypt enc2 (which was never decrypted before).
        byte[] dec = bob2.decrypt(enc2.header, enc2.ciphertext);
        Assertions.assertArrayEquals("m2".getBytes(StandardCharsets.UTF_8), dec,
                "session must survive marshal/unmarshal");
    }

    @Test
    void marshalUnmarshal_continueSending() throws SessionException {
        // Alice sends, Bob decrypts, Alice marshals/unmarshals, continues sending.
        Session.EncryptResult enc0 = alice.encrypt("pre-marshal".getBytes(StandardCharsets.UTF_8));
        bob.decrypt(enc0.header, enc0.ciphertext);

        // Bob replies so Alice's remoteDhPub is set (DH ratchet completed on Alice side).
        Session.EncryptResult bobMsg = bob.encrypt("bob-reply".getBytes(StandardCharsets.UTF_8));
        alice.decrypt(bobMsg.header, bobMsg.ciphertext);

        // Marshal Alice, restore, send another message.
        Session alice2 = Session.unmarshal(alice.marshal());
        Session.EncryptResult enc1 = alice2.encrypt("post-marshal".getBytes(StandardCharsets.UTF_8));
        byte[] dec = bob.decrypt(enc1.header, enc1.ciphertext);
        Assertions.assertArrayEquals("post-marshal".getBytes(StandardCharsets.UTF_8), dec,
                "Alice's session must continue after marshal/unmarshal");
    }

    @Test
    void marshalRoundTrip_deterministic() {
        byte[] blob1 = alice.marshal();
        byte[] blob2 = alice.marshal();
        Assertions.assertArrayEquals(blob1, blob2, "marshal must be deterministic");
    }

    // -------------------------------------------------------------------------
    // Message-header marshal / unmarshal
    // -------------------------------------------------------------------------

    @Test
    void messageHeaderMarshalUnmarshal() {
        byte[] dhPub = X3dhpqCrypto.x25519GenerateKeypair().pub;
        MessageHeader h = new MessageHeader(dhPub, 7L, 42L, new byte[1088], new byte[1184]);
        byte[] bytes = h.marshal();
        MessageHeader h2 = MessageHeader.unmarshal(bytes);
        Assertions.assertEquals(h, h2, "header must survive marshal/unmarshal");
    }

    @Test
    void messageHeaderMarshalUnmarshal_noKem() {
        byte[] dhPub = X3dhpqCrypto.x25519GenerateKeypair().pub;
        MessageHeader h = new MessageHeader(dhPub, 0L, 3L, null, null);
        MessageHeader h2 = MessageHeader.unmarshal(h.marshal());
        Assertions.assertEquals(h, h2);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    // Build a fake PqxdhResult for testing.
    private static PqxdhResult makePqxdhResult(PqxdhResult.Role role,
                                                byte[] rootKey, byte[] chainKey, byte[] ad) {
        return new PqxdhResult(role, rootKey, chainKey, ad, null);
    }

    // Build a symmetric pair of sessions (alice+bob) for tests that need a fresh pair.
    // Returns [alice, bob] where alice is already ratcheted against bob's initial DH.
    private static Session[] makePair(byte[] rootKey, byte[] chainKey, byte[] ad) {
        KeyPair bobDh = X3dhpqCrypto.x25519GenerateKeypair();
        PqxdhResult aliceRes = makePqxdhResult(PqxdhResult.Role.INITIATOR, rootKey, chainKey, ad);
        PqxdhResult bobRes   = makePqxdhResult(PqxdhResult.Role.RESPONDER, rootKey, chainKey, ad);
        Session alice = Session.fromPqxdhSenderWithPeerDh(aliceRes, bobDh.pub);
        Session bob   = Session.fromPqxdhReceiverWithDh(bobRes, bobDh.priv, bobDh.pub);
        return new Session[]{alice, bob};
    }
}
