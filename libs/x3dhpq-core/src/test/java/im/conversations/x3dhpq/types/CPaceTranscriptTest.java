// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

class CPaceTranscriptTest {

    // Test context mirrors testCtx() from cpace_test.go.
    private static final String BARE_JID       = "alice@example.com";
    private static final String INITIATOR_JID  = "alice@example.com/phone";
    private static final String RESPONDER_JID  = "alice@example.com/laptop";
    private static final String DOMAIN         = "example.com";
    private static final byte[] INIT_AIK_PUB   = "init-aik-pub".getBytes(StandardCharsets.UTF_8);
    private static final byte[] RESP_AIK_PUB   = "resp-aik-pub".getBytes(StandardCharsets.UTF_8);
    private static final String PURPOSE        = "device-pairing";

    @Test
    void testTranscriptStartsWithPrefix() {
        byte[] t = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);

        byte[] prefix = CPace.TRANSCRIPT_PREFIX;
        assertTrue(t.length >= prefix.length, "transcript shorter than prefix");
        for (int i = 0; i < prefix.length; i++) {
            assertEquals(prefix[i], t[i], "prefix byte " + i + " mismatch");
        }
    }

    @Test
    void testTranscriptContainsRoleMarkers() {
        byte[] t = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);

        // Role markers 0x49 'I' and 0x52 'R' appear consecutively after the 6 length-prefixed fields.
        boolean foundMarkers = false;
        for (int i = 0; i < t.length - 1; i++) {
            if ((t[i] & 0xff) == 0x49 && (t[i + 1] & 0xff) == 0x52) {
                foundMarkers = true;
                break;
            }
        }
        assertTrue(foundMarkers, "Transcript must contain 0x49 0x52 role markers");
    }

    @Test
    void testTranscriptDeterministic() {
        byte[] t1 = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);
        byte[] t2 = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);
        assertArrayEquals(t1, t2, "buildTranscript must be deterministic");
    }

    @Test
    void testTranscriptVaryingFieldsProduceDifferentOutput() {
        byte[] base = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);

        byte[] diffBare = CPaceTranscript.build(
                "bob@example.com", INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);
        assertFalse(java.util.Arrays.equals(base, diffBare), "Different bareJid must change transcript");

        byte[] diffPurpose = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, "other-purpose");
        assertFalse(java.util.Arrays.equals(base, diffPurpose), "Different purpose must change transcript");

        byte[] diffInitAik = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                new byte[]{0x01, 0x02}, RESP_AIK_PUB, PURPOSE);
        assertFalse(java.util.Arrays.equals(base, diffInitAik), "Different initiatorAik must change transcript");
    }

    @Test
    void testTranscriptKnownVector() throws Exception {
        // Compute the expected transcript by hand, mirroring buildTranscript() exactly.
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.write(CPace.TRANSCRIPT_PREFIX);
        CPaceTranscript.packField(expected, BARE_JID.getBytes(StandardCharsets.UTF_8));
        CPaceTranscript.packField(expected, INITIATOR_JID.getBytes(StandardCharsets.UTF_8));
        CPaceTranscript.packField(expected, RESPONDER_JID.getBytes(StandardCharsets.UTF_8));
        CPaceTranscript.packField(expected, DOMAIN.getBytes(StandardCharsets.UTF_8));
        CPaceTranscript.packField(expected, INIT_AIK_PUB);
        CPaceTranscript.packField(expected, RESP_AIK_PUB);
        expected.write(0x49);
        expected.write(0x52);
        CPaceTranscript.packField(expected, PURPOSE.getBytes(StandardCharsets.UTF_8));

        byte[] got = CPaceTranscript.build(
                BARE_JID, INITIATOR_JID, RESPONDER_JID, DOMAIN,
                INIT_AIK_PUB, RESP_AIK_PUB, PURPOSE);

        assertArrayEquals(expected.toByteArray(), got, "Transcript must match hand-computed vector");
    }

    @Test
    void testTranscriptNullAikTreatedAsEmpty() {
        // Null AIK marshals should be treated as empty byte arrays (length=0).
        byte[] withNull  = CPaceTranscript.build(BARE_JID, "", "", "", null, null, "p");
        byte[] withEmpty = CPaceTranscript.build(BARE_JID, "", "", "", new byte[0], new byte[0], "p");
        assertArrayEquals(withNull, withEmpty, "null and empty AIK must produce same transcript");
    }
}
