// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.BouncyCastleInstaller;
import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.HkdfSha512;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;

/**
 * Pure-JVM end-to-end envelope round-trip tests.
 * Verifies the full encrypt/decrypt path that XmppX3dhpqMessage uses.
 */
class EnvelopeRoundTripTest {

    private static HkdfSha512 HKDF;
    private static KeyPair aliceDik;
    private static KeyPair bobDikX25519;
    private static KeyPair bobSpk;
    private static KemKeyPair bobKemKey;

    @BeforeAll
    static void setUp() {
        BouncyCastleInstaller.ensureRegistered();
        HKDF        = X3dhpqCrypto.HKDF_SHA512;
        aliceDik    = X3dhpqCrypto.x25519GenerateKeypair();
        bobDikX25519= X3dhpqCrypto.x25519GenerateKeypair();
        bobSpk      = X3dhpqCrypto.x25519GenerateKeypair();
        bobKemKey   = X3dhpqCrypto.mlkem768GenerateKeypair();
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    /** Build Bob's BundleData; no OPK. */
    private static BundleData buildBobBundle() {
        return new BundleData(
                new byte[32],   // aikEd25519Pub
                new byte[1952], // aikMldsaPub
                new byte[10],   // dcMarshal
                new byte[32],   // dikEd25519Pub
                bobDikX25519.pub,
                new byte[1952], // dikMldsaPub
                7,              // spkId
                bobSpk.pub,
                new byte[64],   // spkSig
                Collections.singletonList(new BundleData.KemPreKey(1, bobKemKey.pub)),
                Collections.emptyList());
    }

    /**
     * Simulates what XmppX3dhpqMessage.createOutbound + addRecipient does:
     * generate payload key/nonce, AES-GCM encrypt the payload, then
     * use Session.encrypt to encrypt the transport key (payloadKey || payloadNonce).
     * Returns [payloadKey, payloadNonce, payloadCt, hdrBytes, encryptedTransportKey].
     */
    private static byte[][] encryptEnvelope(Session aliceSession, byte[] plaintext) {
        final SecureRandom rng = new SecureRandom();
        final byte[] payloadKey   = new byte[32];
        final byte[] payloadNonce = new byte[12];
        rng.nextBytes(payloadKey);
        rng.nextBytes(payloadNonce);

        // encrypt payload with empty AAD (matches dino-fork manager.vala:215)
        final byte[] payloadCt = X3dhpqCrypto.aes256gcmEncrypt(
                payloadKey, payloadNonce, plaintext, new byte[0]);

        // transport key = payloadKey(32) || payloadNonce(12)
        final byte[] transportKey = concat(payloadKey, payloadNonce);
        final Session.EncryptResult enc = aliceSession.encrypt(transportKey);

        return new byte[][]{
                payloadKey, payloadNonce, payloadCt,
                enc.header.marshal(), enc.ciphertext};
    }

    /**
     * Simulates what XmppX3dhpqMessage.decrypt does:
     * decrypt transport key via session, split into payloadKey/nonce,
     * then AES-GCM decrypt the payload.
     */
    private static byte[] decryptEnvelope(
            Session bobSession, byte[] hdrBytes, byte[] encTransportKey, byte[] payloadCt)
            throws SessionException {
        final MessageHeader header = MessageHeader.unmarshal(hdrBytes);
        final byte[] transportKey = bobSession.decrypt(header, encTransportKey);
        final byte[] pKey   = Arrays.copyOf(transportKey, 32);
        final byte[] pNonce = Arrays.copyOfRange(transportKey, 32, 44);
        return X3dhpqCrypto.aes256gcmDecrypt(pKey, pNonce, payloadCt, new byte[0]);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    /** First-message path: PQXDH bootstrap + encrypt/decrypt "hello world". */
    @Test
    void firstMessage_aliceToBobDecryptsCorrectly() throws SessionException {
        final BundleData bobBundle = buildBobBundle();

        // Alice runs PQXDH initiator
        final PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);

        final PrekeyEnvelope env = aliceResult.getEnvelope();
        Assertions.assertNotNull(env, "initiator must produce a prekey envelope");

        // Alice creates sending session; pre-ratchets with Bob's SPK
        final Session aliceSession = Session.fromPqxdhSenderWithPeerDh(aliceResult, bobSpk.pub);

        // Bob runs PQXDH responder
        final PqxdhResult bobResult = PqxdhResponder.respond(
                bobSpk.priv,
                bobDikX25519.priv,
                bobDikX25519.pub,
                bobKemKey.priv,
                null, // no OPK
                aliceDik.pub,
                env.ephemeralPub,
                env.kemCiphertext,
                HKDF);

        // Bob creates receiving session; uses bobSpk as initial DH keypair
        final Session bobSession = Session.fromPqxdhReceiverWithDh(
                bobResult, bobSpk.priv, bobSpk.pub);

        // Alice encrypts "hello world"
        final byte[] plaintext = "hello world".getBytes(StandardCharsets.UTF_8);
        final byte[][] envelope = encryptEnvelope(aliceSession, plaintext);
        final byte[] hdrBytes         = envelope[3];
        final byte[] encTransportKey  = envelope[4];
        final byte[] payloadCt        = envelope[2];

        // Bob decrypts
        final byte[] decrypted = decryptEnvelope(bobSession, hdrBytes, encTransportKey, payloadCt);
        Assertions.assertArrayEquals(plaintext, decrypted, "Bob must recover Alice's plaintext");
    }

    /** Subsequent message path: sessions are already established (no prekey block). */
    @Test
    void subsequentMessage_noPrekey_decryptsCorrectly() throws SessionException {
        final BundleData bobBundle = buildBobBundle();

        final PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);

        final PrekeyEnvelope env = aliceResult.getEnvelope();
        final Session aliceSession = Session.fromPqxdhSenderWithPeerDh(aliceResult, bobSpk.pub);

        final PqxdhResult bobResult = PqxdhResponder.respond(
                bobSpk.priv, bobDikX25519.priv, bobDikX25519.pub,
                bobKemKey.priv, null, aliceDik.pub,
                env.ephemeralPub, env.kemCiphertext, HKDF);
        final Session bobSession = Session.fromPqxdhReceiverWithDh(
                bobResult, bobSpk.priv, bobSpk.pub);

        // Send first message to bootstrap Bob's ratchet state
        final byte[] msg1 = "ping".getBytes(StandardCharsets.UTF_8);
        final byte[][] env1 = encryptEnvelope(aliceSession, msg1);
        decryptEnvelope(bobSession, env1[3], env1[4], env1[2]);

        // Send second message — no prekey needed, session already established
        final byte[] msg2 = "subsequent message".getBytes(StandardCharsets.UTF_8);
        final byte[][] env2 = encryptEnvelope(aliceSession, msg2);

        final byte[] decrypted = decryptEnvelope(bobSession, env2[3], env2[4], env2[2]);
        Assertions.assertArrayEquals(msg2, decrypted,
                "Bob must decrypt subsequent message without prekey");
    }

    /** Bob replies to Alice: bidirectional exchange works. */
    @Test
    void bidirectionalExchange_aliceAndBobBothDecrypt() throws SessionException {
        final BundleData bobBundle = buildBobBundle();

        final PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);

        final PrekeyEnvelope env = aliceResult.getEnvelope();
        final Session aliceSession = Session.fromPqxdhSenderWithPeerDh(aliceResult, bobSpk.pub);

        final PqxdhResult bobResult = PqxdhResponder.respond(
                bobSpk.priv, bobDikX25519.priv, bobDikX25519.pub,
                bobKemKey.priv, null, aliceDik.pub,
                env.ephemeralPub, env.kemCiphertext, HKDF);
        final Session bobSession = Session.fromPqxdhReceiverWithDh(
                bobResult, bobSpk.priv, bobSpk.pub);

        // Alice → Bob
        final byte[] hello = "hello".getBytes(StandardCharsets.UTF_8);
        final byte[][] e1 = encryptEnvelope(aliceSession, hello);
        final byte[] dec1 = decryptEnvelope(bobSession, e1[3], e1[4], e1[2]);
        Assertions.assertArrayEquals(hello, dec1, "Bob must decrypt Alice's first message");

        // Bob → Alice
        final byte[] reply = "world".getBytes(StandardCharsets.UTF_8);
        final byte[][] e2 = encryptEnvelope(bobSession, reply);
        final byte[] dec2 = decryptEnvelope(aliceSession, e2[3], e2[4], e2[2]);
        Assertions.assertArrayEquals(reply, dec2, "Alice must decrypt Bob's reply");
    }

    /** Payload key/nonce round-trip: AES-256-GCM with empty AAD. */
    @Test
    void payloadKeyNonce_aesGcmRoundTrip() {
        final SecureRandom rng = new SecureRandom();
        final byte[] key   = new byte[32];
        final byte[] nonce = new byte[12];
        rng.nextBytes(key);
        rng.nextBytes(nonce);
        final byte[] plain = "test payload".getBytes(StandardCharsets.UTF_8);
        final byte[] ct    = X3dhpqCrypto.aes256gcmEncrypt(key, nonce, plain, new byte[0]);
        final byte[] dec   = X3dhpqCrypto.aes256gcmDecrypt(key, nonce, ct, new byte[0]);
        Assertions.assertArrayEquals(plain, dec, "AES-GCM round-trip with empty AAD must recover plaintext");
    }

    /** Transport key marshal/unmarshal: 44-byte blob splits correctly. */
    @Test
    void transportKey_splitAndReassemble() {
        final SecureRandom rng = new SecureRandom();
        final byte[] payloadKey   = new byte[32];
        final byte[] payloadNonce = new byte[12];
        rng.nextBytes(payloadKey);
        rng.nextBytes(payloadNonce);

        final byte[] transportKey = concat(payloadKey, payloadNonce);
        Assertions.assertEquals(44, transportKey.length, "transport key must be 44 bytes");

        final byte[] splitKey   = Arrays.copyOf(transportKey, 32);
        final byte[] splitNonce = Arrays.copyOfRange(transportKey, 32, 44);

        Assertions.assertArrayEquals(payloadKey,   splitKey,   "split key must match original");
        Assertions.assertArrayEquals(payloadNonce, splitNonce, "split nonce must match original");
    }
}
