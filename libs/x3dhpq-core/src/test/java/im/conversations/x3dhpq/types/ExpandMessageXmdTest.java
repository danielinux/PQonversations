// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ExpandMessageXmdTest {

    // Vectors are locked-in: generated from the Go reference (expandMessageXMDSHA512
    // in elligator2.go). Regenerate from Go if the Java implementation changes.

    // Vector 1: msg="abc", dst="QUUX-V01-CS02-with-expander-SHA512", lenInBytes=64
    // Matches RFC 9380 Appendix K.5 test vector (SHA-512 expander).
    private static final String VECTOR1_HEX =
            "9465061b70f2462ecc82feec74feba8b424e8fb8d077c6de2e3af4dd3f27f366"
          + "29b157fff8d3b37374620b9d01bbd5280593d64aee7ced9eb73954065d0bdc70";

    // Vector 2: msg=empty, dst="X3DHPQ-CPace-v1", lenInBytes=48
    // This is the actual hashToCurveX25519 code path size used by CPace.
    private static final String VECTOR2_HEX =
            "e1e270e31a1660f9b1f53bd319d4ffc7c3d1bf2e3b369ac99fa0c609608bf27"
          + "221ca2c81698b21c484f4630e726d7de9";

    @Test
    void vector1AbcExpander64() {
        byte[] out = ExpandMessageXmd.expand(
                "abc".getBytes(),
                "QUUX-V01-CS02-with-expander-SHA512".getBytes(),
                64);
        Assertions.assertEquals(64, out.length);
        Assertions.assertEquals(VECTOR1_HEX, hex(out), "Vector 1 mismatch");
    }

    @Test
    void vector2EmptyMsgCPace48() {
        byte[] out = ExpandMessageXmd.expand(
                new byte[0],
                "X3DHPQ-CPace-v1".getBytes(),
                48);
        Assertions.assertEquals(48, out.length);
        Assertions.assertEquals(VECTOR2_HEX, hex(out), "Vector 2 mismatch");
    }

    @Test
    void outputLengthMatchesRequest() {
        for (int len : new int[]{1, 32, 64, 128, 200}) {
            byte[] out = ExpandMessageXmd.expand(
                    "msg".getBytes(), "DST".getBytes(), len);
            Assertions.assertEquals(len, out.length,
                    "Output length must equal lenInBytes for len=" + len);
        }
    }

    @Test
    void negativeLenInBytesTooLarge() {
        Assertions.assertThrows(IllegalArgumentException.class, () ->
                ExpandMessageXmd.expand("msg".getBytes(), "DST".getBytes(), 70000));
    }

    @Test
    void negativeDstTooLong() {
        byte[] longDst = new byte[256];
        Assertions.assertThrows(IllegalArgumentException.class, () ->
                ExpandMessageXmd.expand("msg".getBytes(), longDst, 32));
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }
}
