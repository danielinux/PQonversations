// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class CPaceTest {

    @Test
    void testDstBytes() {
        // cpace.go: const cpaceDST = "X3DHPQ-CPace-v1"
        byte[] expected = "X3DHPQ-CPace-v1".getBytes(StandardCharsets.US_ASCII);
        assertArrayEquals(expected, CPace.DST, "DST must match Go const cpaceDST");
    }

    @Test
    void testTranscriptPrefixBytes() {
        // cpace.go: []byte("X3DHPQ-CPace-Transcript-v1\x00")
        byte[] base = "X3DHPQ-CPace-Transcript-v1".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = new byte[base.length + 1];
        System.arraycopy(base, 0, expected, 0, base.length);
        expected[base.length] = 0x00;
        assertArrayEquals(expected, CPace.TRANSCRIPT_PREFIX,
                "TRANSCRIPT_PREFIX must be ASCII string with trailing NUL");
    }

    @Test
    void testTranscriptPrefixLength() {
        // "X3DHPQ-CPace-Transcript-v1" = 26 chars + 1 NUL = 27 bytes
        assertEquals(27, CPace.TRANSCRIPT_PREFIX.length);
    }

    @Test
    void testDstLength() {
        assertEquals(15, CPace.DST.length);
    }

    @Test
    void testLowOrderPointCount() {
        assertEquals(7, CPace.LOW_ORDER_POINTS.length,
                "Must have exactly 7 low-order points (RFC 7748 §7)");
    }

    @Test
    void testLowOrderPointLengths() {
        for (byte[] pt : CPace.LOW_ORDER_POINTS) {
            assertEquals(32, pt.length, "Each low-order point must be 32 bytes");
        }
    }

    @Test
    void testIsLowOrderPointForEachKnownPoint() {
        for (byte[] pt : CPace.LOW_ORDER_POINTS) {
            assertTrue(CPace.isLowOrderPoint(pt),
                    "Known low-order point not detected: " + Arrays.toString(pt));
        }
    }

    @Test
    void testIsLowOrderPointNegative() {
        // Arbitrary 32-byte buffer that is not a low-order point.
        // The Curve25519 base point u=9 in little-endian.
        byte[] basePoint = new byte[32];
        basePoint[0] = 9;
        assertFalse(CPace.isLowOrderPoint(basePoint), "Base point must not be classified as low-order");
    }

    @Test
    void testIsLowOrderPointNullSafe() {
        assertFalse(CPace.isLowOrderPoint(null));
        assertFalse(CPace.isLowOrderPoint(new byte[31]));
        assertFalse(CPace.isLowOrderPoint(new byte[33]));
    }

    @Test
    void testLowOrderPoint0AllZeros() {
        byte[] pt = CPace.LOW_ORDER_POINTS[0];
        for (byte b : pt) assertEquals(0, b, "First low-order point must be all-zeros");
    }

    @Test
    void testLowOrderPoint1IsOne() {
        byte[] pt = CPace.LOW_ORDER_POINTS[1];
        assertEquals(1, pt[0] & 0xff);
        for (int i = 1; i < 32; i++) assertEquals(0, pt[i], "Bytes 1..31 must be zero");
    }

    @Test
    void testSessionTranscriptPrefixBytes() {
        // cpace.go: []byte("X3DHPQ-CPace-SessionTranscript-v1\x00")
        byte[] base = "X3DHPQ-CPace-SessionTranscript-v1".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = new byte[base.length + 1];
        System.arraycopy(base, 0, expected, 0, base.length);
        expected[base.length] = 0x00;
        assertArrayEquals(expected, CPace.SESSION_TRANSCRIPT_PREFIX);
    }
}
