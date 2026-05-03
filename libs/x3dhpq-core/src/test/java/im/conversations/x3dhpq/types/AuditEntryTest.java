// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

class AuditEntryTest {

    // Build a realistic dummy AuditEntry with all fields populated.
    private AuditEntry makeEntry(long seq, byte fillPrev, int action, byte[] payload, long ts) {
        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, fillPrev);
        byte[] sigEd    = new byte[64];  Arrays.fill(sigEd, (byte) 0xAA);
        byte[] sigMLDSA = new byte[3293]; Arrays.fill(sigMLDSA, (byte) 0xBB);
        return new AuditEntry(seq, prevHash, action, payload, ts, sigEd, sigMLDSA);
    }

    @Test
    void testRoundTrip() {
        byte[] payload = {0x01, 0x02, 0x03, 0x04};
        AuditEntry orig = makeEntry(42L, (byte) 0x11, AuditEntry.ACTION_ADD_DEVICE, payload, 1700000000L);

        byte[] wire  = orig.marshal();
        AuditEntry decoded = AuditEntry.unmarshal(wire);

        assertEquals(orig.getSeq(), decoded.getSeq());
        assertArrayEquals(orig.getPrevHash(), decoded.getPrevHash());
        assertEquals(orig.getAction(), decoded.getAction());
        assertArrayEquals(orig.getPayload(), decoded.getPayload());
        assertEquals(orig.getTimestamp(), decoded.getTimestamp());
        assertArrayEquals(orig.getSigEd25519(), decoded.getSigEd25519());
        assertArrayEquals(orig.getSigMLDSA(), decoded.getSigMLDSA());
        assertEquals(orig, decoded);
    }

    @Test
    void testSignedPartVector_A4() {
        // Lock down Appendix-A vector A.4
        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, (byte) 0x55);
        byte[] payload = {
            0x00, 0x00, 0x01, 0x23,
            0x00, 0x00, 0x00, 0x06,
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 0x00, 0x01
        };
        AuditEntry entry = new AuditEntry(7L, prevHash, AuditEntry.ACTION_ADD_DEVICE, payload, 1714483200L, null, null);

        String got = AppendixAValidator.bytesToHex(entry.signedPart());
        String want =
                "5833444850512d41756469742d763100" +
                "0000000000000007" +
                "5555555555555555555555555555555555555555555555555555555555555555" +
                "01" +
                "0000000e" +
                "0000012300000006deadbeef0001" +
                "000000006630f000";
        assertEquals(want, got);
    }

    @Test
    void testPrefixLength() {
        // Prefix must be exactly 16 bytes
        assertEquals(16, AuditEntry.AUDIT_PREFIX.length);
    }

    @Test
    void testEmptyPayloadRoundTrip() {
        AuditEntry e = makeEntry(0L, (byte) 0x00, AuditEntry.ACTION_ROTATE_AIK, new byte[0], 0L);
        assertEquals(e, AuditEntry.unmarshal(e.marshal()));
    }

    @Test
    void testAllActionConstants() {
        // action constants must match Go values
        assertEquals(1, AuditEntry.ACTION_ADD_DEVICE);
        assertEquals(2, AuditEntry.ACTION_REMOVE_DEVICE);
        assertEquals(3, AuditEntry.ACTION_ROTATE_AIK);
        assertEquals(4, AuditEntry.ACTION_RECOVER_FROM_BACKUP);
    }

    @Test
    void testComputeNextHash() {
        // computeNextHash(marshal) is deterministic
        AuditEntry e = makeEntry(1L, (byte) 0xAA, AuditEntry.ACTION_ADD_DEVICE, new byte[]{0x01}, 1L);
        byte[] wire = e.marshal();
        InlineSha256 sha = new InlineSha256();
        byte[] h1 = AuditEntry.computeNextHash(wire, sha);
        byte[] h2 = AuditEntry.computeNextHash(wire, sha);
        assertArrayEquals(h1, h2);
        assertEquals(32, h1.length);
    }

    @Test
    void testUnmarshalTooShort() {
        assertThrows(IllegalArgumentException.class, () -> AuditEntry.unmarshal(new byte[5]));
    }

    @Test
    void testUnmarshalWrongPrefix() {
        byte[] raw = new byte[80];
        raw[0] = 'X'; raw[1] = 'X'; // wrong prefix
        assertThrows(IllegalArgumentException.class, () -> AuditEntry.unmarshal(raw));
    }

    @Test
    void testPrevHashMustBe32Bytes() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuditEntry(0, new byte[31], 1, null, 0, null, null));
    }
}
