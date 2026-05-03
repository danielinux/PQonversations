// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.HkdfSha512;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

// End-to-end PQXDH round-trip tests; all crypto is BouncyCastle, no Android dependencies.
class PqxdhRoundTripTest {

    // Use the production HKDF-SHA-512 static adapter; no test helper needed.
    private static HkdfSha512 HKDF;

    // Bob's (responder's) key material.
    private static KeyPair bobDikX25519;
    private static KeyPair bobSpk;
    private static KemKeyPair bobKemKey;
    private static KeyPair bobOpk;

    // Alice's (initiator's) key material.
    private static KeyPair aliceDik;

    @BeforeAll
    static void setUp() {
        // Production static adapter; backed by BouncyCastle SHA-512.
        HKDF = X3dhpqCrypto.HKDF_SHA512;
        bobDikX25519 = X3dhpqCrypto.x25519GenerateKeypair();
        bobSpk = X3dhpqCrypto.x25519GenerateKeypair();
        bobKemKey = X3dhpqCrypto.mlkem768GenerateKeypair();
        bobOpk = X3dhpqCrypto.x25519GenerateKeypair();
        aliceDik = X3dhpqCrypto.x25519GenerateKeypair();
    }

    // Build a BundleData from Bob's keys, optionally including an OPK.
    private static BundleData buildBobBundle(boolean includeOpk) {
        // AIK/DC fields are not used by the DH computation; pass dummy bytes.
        return new BundleData(
                new byte[32], // aikEd25519Pub
                new byte[1952], // aikMldsaPub
                new byte[10], // dcMarshal
                new byte[32], // dikEd25519Pub
                bobDikX25519.pub, // dikX25519Pub — used in dh2
                new byte[1952], // dikMldsaPub
                7, // spkId
                bobSpk.pub, // spkPub — used in dh1 and dh3
                new byte[64], // spkSig
                Collections.singletonList(new BundleData.KemPreKey(1, bobKemKey.pub)),
                includeOpk
                        ? Collections.singletonList(new BundleData.OneTimePreKey(42, bobOpk.pub))
                        : Collections.emptyList());
    }

    @Test
    void roundTripWithOpk_rootKeyMatches() {
        BundleData bobBundle = buildBobBundle(true);

        // Alice initiates.
        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], // dikEd25519Pub (not used in crypto, goes to envelope)
                new byte[10], // dcMarshal
                new byte[32], // aikEd25519Pub
                new byte[1952], // aikMldsaPub
                bobBundle,
                HKDF);

        PrekeyEnvelope env = aliceResult.getEnvelope();
        Assertions.assertNotNull(env, "initiator must produce an envelope");

        // Bob responds.
        PqxdhResult bobResult = PqxdhResponder.respond(
                bobSpk.priv,
                bobDikX25519.priv,
                bobDikX25519.pub,
                bobKemKey.priv,
                bobOpk.priv, // OPK was used; opkId=42
                aliceDik.pub, // peer (Alice) DIK X25519 pub — from envelope/DC
                env.ephemeralPub,
                env.kemCiphertext,
                HKDF);

        // Root keys must match.
        Assertions.assertArrayEquals(
                aliceResult.getRootKey(), bobResult.getRootKey(),
                "root keys must match");

        // Chain keys must match: Alice's initial chain key == Bob's initial chain key
        // (Alice sends, Bob receives — both derive the same 32 bytes from okm[32:64]).
        Assertions.assertArrayEquals(
                aliceResult.getInitialChainKey(), bobResult.getInitialChainKey(),
                "initial chain keys must match");

        // AD must match.
        Assertions.assertArrayEquals(
                aliceResult.getAd(), bobResult.getAd(),
                "associated data must match");
    }

    @Test
    void roundTripWithoutOpk_rootKeyMatches() {
        BundleData bobBundle = buildBobBundle(false);

        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);

        PrekeyEnvelope env = aliceResult.getEnvelope();
        // opkId must be 0 when no OPK was in the bundle.
        Assertions.assertEquals(0, env.opkId, "opkId must be 0 when no OPK used");

        PqxdhResult bobResult = PqxdhResponder.respond(
                bobSpk.priv,
                bobDikX25519.priv,
                bobDikX25519.pub,
                bobKemKey.priv,
                null, // no OPK
                aliceDik.pub,
                env.ephemeralPub,
                env.kemCiphertext,
                HKDF);

        Assertions.assertArrayEquals(
                aliceResult.getRootKey(), bobResult.getRootKey(),
                "root keys must match (no OPK)");

        Assertions.assertArrayEquals(
                aliceResult.getInitialChainKey(), bobResult.getInitialChainKey(),
                "chain keys must match (no OPK)");
    }

    @Test
    void tamperedKemCt_producesDifferentRootKey() {
        BundleData bobBundle = buildBobBundle(false);

        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);

        PrekeyEnvelope env = aliceResult.getEnvelope();

        // Tamper the ciphertext.
        byte[] tamperedCt = Arrays.copyOf(env.kemCiphertext, env.kemCiphertext.length);
        tamperedCt[0] ^= 0xFF;

        PqxdhResult bobResult = PqxdhResponder.respond(
                bobSpk.priv, bobDikX25519.priv, bobDikX25519.pub,
                bobKemKey.priv, null,
                aliceDik.pub, env.ephemeralPub, tamperedCt, HKDF);

        // Tampered KEM CT causes decaps to return a random (implicit rejection) secret,
        // so root keys diverge.
        Assertions.assertFalse(
                Arrays.equals(aliceResult.getRootKey(), bobResult.getRootKey()),
                "tampered KEM CT must produce a different root key");
    }

    @Test
    void missingOpkOnResponderSide_producesDifferentRootKey() {
        // Alice uses an OPK but Bob claims to have none (simulates a missing / consumed OPK).
        BundleData bobBundle = buildBobBundle(true); // Alice sees an OPK

        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);

        PrekeyEnvelope env = aliceResult.getEnvelope();

        // Bob omits the OPK (null) even though Alice included dh4.
        PqxdhResult bobResult = PqxdhResponder.respond(
                bobSpk.priv, bobDikX25519.priv, bobDikX25519.pub,
                bobKemKey.priv, null, // OPK omitted
                aliceDik.pub, env.ephemeralPub, env.kemCiphertext, HKDF);

        Assertions.assertFalse(
                Arrays.equals(aliceResult.getRootKey(), bobResult.getRootKey()),
                "omitting OPK on responder side must diverge from initiator's root key");
    }

    @Test
    void envelopeCarriesCorrectKemKeyId() {
        BundleData bobBundle = buildBobBundle(false);
        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);
        // kemPreKeys[0].id = 1
        Assertions.assertEquals(1, aliceResult.getEnvelope().kemKeyId,
                "envelope must carry the chosen KEM pre-key id");
    }

    @Test
    void adIs64Bytes() {
        BundleData bobBundle = buildBobBundle(false);
        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);
        Assertions.assertEquals(64, aliceResult.getAd().length, "AD must be 64 bytes");
    }

    @Test
    void rootKeyIs32Bytes() {
        BundleData bobBundle = buildBobBundle(false);
        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.priv, aliceDik.pub,
                new byte[32], new byte[10], new byte[32], new byte[1952],
                bobBundle, HKDF);
        Assertions.assertEquals(32, aliceResult.getRootKey().length, "rootKey must be 32 bytes");
        Assertions.assertEquals(32, aliceResult.getInitialChainKey().length,
                "initialChainKey must be 32 bytes");
    }
}
