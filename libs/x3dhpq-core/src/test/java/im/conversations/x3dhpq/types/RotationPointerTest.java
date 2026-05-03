// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

class RotationPointerTest {

    private AccountIdentityPub makeAik(byte fill) {
        byte[] ed    = new byte[32];   Arrays.fill(ed, fill);
        byte[] mldsa = new byte[1952]; Arrays.fill(mldsa, (byte)(fill ^ 0x55));
        return new AccountIdentityPub(ed, mldsa);
    }

    private RotationPointer makePointer(String reason) {
        AccountIdentityPub oldAik = makeAik((byte) 0x11);
        AccountIdentityPub newAik = makeAik((byte) 0x22);
        byte[] sigEd    = new byte[64];   Arrays.fill(sigEd, (byte) 0xAA);
        byte[] sigMLDSA = new byte[3293]; Arrays.fill(sigMLDSA, (byte) 0xBB);
        return new RotationPointer(1, oldAik, newAik, 1714500000L, reason, sigEd, sigMLDSA);
    }

    @Test
    void testRoundTrip() {
        RotationPointer orig = makePointer("scheduled rotation");
        byte[] wire = orig.marshal();
        RotationPointer decoded = RotationPointer.unmarshal(wire);

        assertEquals(orig.getVersion(), decoded.getVersion());
        assertEquals(orig.getRotatedAt(), decoded.getRotatedAt());
        assertEquals(orig.getReason(), decoded.getReason());
        assertArrayEquals(orig.getSigEd25519(), decoded.getSigEd25519());
        assertArrayEquals(orig.getSigMLDSA(), decoded.getSigMLDSA());
        assertTrue(orig.getOldAikPub().equals(decoded.getOldAikPub()));
        assertTrue(orig.getNewAikPub().equals(decoded.getNewAikPub()));
    }

    @Test
    void testEmptyReason() {
        RotationPointer rp = makePointer("");
        assertEquals("", RotationPointer.unmarshal(rp.marshal()).getReason());
    }

    @Test
    void testMaxReasonAllowed() {
        // 512 bytes of UTF-8 ASCII is OK
        String maxReason = "a".repeat(512);
        RotationPointer rp = makePointer(maxReason);
        assertEquals(maxReason, RotationPointer.unmarshal(rp.marshal()).getReason());
    }

    @Test
    void testReasonTooLong() {
        assertThrows(IllegalArgumentException.class, () -> makePointer("a".repeat(513)));
    }

    @Test
    void testPrefixLength() {
        // "X3DHPQ-Rotation-v1\x00" = 19 bytes
        assertEquals(19, RotationPointer.ROTATION_PREFIX.length);
    }

    @Test
    void testUnmarshalWrongPrefix() {
        byte[] wire = makePointer("test").marshal();
        wire[0] = 'Y'; // corrupt prefix
        assertThrows(IllegalArgumentException.class, () -> RotationPointer.unmarshal(wire));
    }

    @Test
    void testNullAikRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new RotationPointer(1, null, makeAik((byte) 0x22), 0L, "", null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new RotationPointer(1, makeAik((byte) 0x11), null, 0L, "", null, null));
    }
}
