// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class CPaceCryptoTest {

    // Shared context fields used across tests.
    private static final String BARE_JID      = "alice@example.com";
    private static final String INIT_JID      = "alice@example.com/phone";
    private static final String RESP_JID      = "alice@example.com/laptop";
    private static final String DOMAIN        = "example.com";
    private static final byte[] INIT_AIK_PUB  = "init-aik-pub".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESP_AIK_PUB  = "resp-aik-pub".getBytes(StandardCharsets.UTF_8);
    private static final String PURPOSE       = "device-pairing";
    private static final byte[] PASSWORD      = "correct-horse-battery-staple".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SID           = "session-id-12345".getBytes(StandardCharsets.UTF_8);

    private static CPaceState initiatorState(byte[] password, byte[] sid) {
        return CPaceCrypto.newSession(
                CPaceRole.INITIATOR, password, sid,
                BARE_JID, INIT_JID, RESP_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);
    }

    private static CPaceState responderState(byte[] password, byte[] sid) {
        return CPaceCrypto.newSession(
                CPaceRole.RESPONDER, password, sid,
                BARE_JID, INIT_JID, RESP_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);
    }

    // Test 1: Both parties with the same password and sid arrive at the same sessionKey.
    @Test
    void testRoundTripSessionKeysMatch() throws Exception {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceState R = responderState(PASSWORD, SID);

        byte[] msgI = CPaceCrypto.message1(I, rng);
        byte[] msgR = CPaceCrypto.message1(R, rng);

        assertEquals(32, msgI.length);
        assertEquals(32, msgR.length);

        byte[] keyI = CPaceCrypto.process(I, msgR);
        byte[] keyR = CPaceCrypto.process(R, msgI);

        assertNotNull(keyI);
        assertNotNull(keyR);
        assertEquals(32, keyI.length);
        assertEquals(32, keyR.length);
        assertArrayEquals(keyI, keyR, "Both parties must derive the same session key");
    }

    // Test 2: Different passwords → session keys are NOT equal.
    @Test
    void testWrongPasswordProducesDifferentSessionKey() throws Exception {
        SecureRandom rng = new SecureRandom();

        byte[] wrongPassword = "wrong-password".getBytes(StandardCharsets.UTF_8);

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceState R = responderState(wrongPassword, SID);

        byte[] msgI = CPaceCrypto.message1(I, rng);
        byte[] msgR = CPaceCrypto.message1(R, rng);

        byte[] keyI = CPaceCrypto.process(I, msgR);
        byte[] keyR = CPaceCrypto.process(R, msgI);

        assertFalse(java.util.Arrays.equals(keyI, keyR),
                "Different passwords must not produce equal session keys");
    }

    // Test 3a: Initiator's confirm tag verifies on responder side.
    @Test
    void testConfirmRoundTripInitiatorToResponder() throws Exception {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceState R = responderState(PASSWORD, SID);

        byte[] msgI = CPaceCrypto.message1(I, rng);
        byte[] msgR = CPaceCrypto.message1(R, rng);

        byte[] keyI = CPaceCrypto.process(I, msgR);
        CPaceCrypto.process(R, msgI);

        byte[] tagFromI = CPaceCrypto.confirm(I, keyI);
        assertEquals(16, tagFromI.length);

        // R verifies I's confirm tag using its own copy of sessionKey (same value as keyI).
        CPaceState R2 = responderState(PASSWORD, SID);
        byte[] msgI2 = CPaceCrypto.message1(I = initiatorState(PASSWORD, SID), rng);
        byte[] msgR2 = CPaceCrypto.message1(R2, rng);
        byte[] keyI2 = CPaceCrypto.process(I, msgR2);
        byte[] keyR2 = CPaceCrypto.process(R2, msgI2);

        byte[] tagI2 = CPaceCrypto.confirm(I, keyI2);
        assertTrue(CPaceCrypto.verifyConfirm(R2, keyR2, tagI2),
                "Responder must accept initiator's confirm tag");
    }

    // Test 3b: Responder's confirm tag verifies on initiator side.
    @Test
    void testConfirmRoundTripResponderToInitiator() throws Exception {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceState R = responderState(PASSWORD, SID);

        byte[] msgI = CPaceCrypto.message1(I, rng);
        byte[] msgR = CPaceCrypto.message1(R, rng);

        byte[] keyI = CPaceCrypto.process(I, msgR);
        byte[] keyR = CPaceCrypto.process(R, msgI);

        byte[] tagFromR = CPaceCrypto.confirm(R, keyR);
        assertEquals(16, tagFromR.length);

        assertTrue(CPaceCrypto.verifyConfirm(I, keyI, tagFromR),
                "Initiator must accept responder's confirm tag");
    }

    // Test 4: A random 16-byte tag is rejected by verifyConfirm.
    @Test
    void testWrongTagRejected() throws Exception {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceState R = responderState(PASSWORD, SID);

        byte[] msgI = CPaceCrypto.message1(I, rng);
        byte[] msgR = CPaceCrypto.message1(R, rng);

        byte[] keyI = CPaceCrypto.process(I, msgR);
        CPaceCrypto.process(R, msgI);

        byte[] garbage = new byte[16];
        rng.nextBytes(garbage);

        assertFalse(CPaceCrypto.verifyConfirm(I, keyI, garbage),
                "Random tag must not pass verifyConfirm");
    }

    // Test 5: A known low-order point is rejected by process().
    @Test
    void testLowOrderPeerMessageThrows() {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceCrypto.message1(I, rng);

        byte[] lowOrder = CPace.LOW_ORDER_POINTS[0];
        assertThrows(CPaceCrypto.CPaceException.class,
                () -> CPaceCrypto.process(I, lowOrder),
                "Low-order peer message must throw CPaceException");
    }

    // Test 6: Wrong-length peer message (not 32 bytes) is rejected.
    @Test
    void testMalformedPeerMessageLengthThrows() {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceCrypto.message1(I, rng);

        byte[] bad = new byte[31];
        assertThrows(CPaceCrypto.CPaceException.class,
                () -> CPaceCrypto.process(I, bad),
                "31-byte peer message must throw CPaceException");
    }

    // Test 7: All 7 low-order points are rejected.
    @Test
    void testAllLowOrderPointsRejected() {
        SecureRandom rng = new SecureRandom();

        for (byte[] lop : CPace.LOW_ORDER_POINTS) {
            CPaceState I = initiatorState(PASSWORD, SID);
            CPaceCrypto.message1(I, rng);
            assertThrows(CPaceCrypto.CPaceException.class,
                    () -> CPaceCrypto.process(I, lop),
                    "Low-order point must be rejected");
        }
    }

    // Test 8: Confirm tags for INITIATOR and RESPONDER are different (different labels).
    @Test
    void testConfirmTagsAreDifferentForEachRole() throws Exception {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceState R = responderState(PASSWORD, SID);

        byte[] msgI = CPaceCrypto.message1(I, rng);
        byte[] msgR = CPaceCrypto.message1(R, rng);

        byte[] keyI = CPaceCrypto.process(I, msgR);
        byte[] keyR = CPaceCrypto.process(R, msgI);

        byte[] tagI = CPaceCrypto.confirm(I, keyI);
        byte[] tagR = CPaceCrypto.confirm(R, keyR);

        assertFalse(java.util.Arrays.equals(tagI, tagR),
                "INITIATOR and RESPONDER confirm tags must differ (different HKDF labels)");
    }

    // Test 9: newSession is deterministic for same inputs.
    @Test
    void testNewSessionIsDeterministic() {
        CPaceState s1 = initiatorState(PASSWORD, SID);
        CPaceState s2 = initiatorState(PASSWORD, SID);
        assertArrayEquals(s1.getG(), s2.getG(), "Generator G must be deterministic");
        assertArrayEquals(s1.getTranscript(), s2.getTranscript(), "Transcript must be deterministic");
    }

    // Test 10: Session key is 32 bytes and not all-zeros.
    @Test
    void testSessionKeyLengthAndNonZero() throws Exception {
        SecureRandom rng = new SecureRandom();

        CPaceState I = initiatorState(PASSWORD, SID);
        CPaceState R = responderState(PASSWORD, SID);

        byte[] msgI = CPaceCrypto.message1(I, rng);
        byte[] msgR = CPaceCrypto.message1(R, rng);

        byte[] keyI = CPaceCrypto.process(I, msgR);
        assertEquals(32, keyI.length);

        boolean allZero = true;
        for (byte b : keyI) if (b != 0) { allZero = false; break; }
        assertFalse(allZero, "Session key must not be all-zeros");
    }
}
