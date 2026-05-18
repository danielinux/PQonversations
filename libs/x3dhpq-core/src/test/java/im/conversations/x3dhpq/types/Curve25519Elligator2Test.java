// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

// Test vectors: regenerate from Go reference if Java impl changes.
// Cross-reference: go test -run TestHashToCurveX25519 ./internal/x3dhpqcrypto/
class Curve25519Elligator2Test {

    private static final byte[] DST = "X3DHPQ-CPace-v1".getBytes(StandardCharsets.US_ASCII);

    // Vector 1: hashToCurveX25519(empty, DST)  — CPace generator-derivation input
    private static final String VEC1_HEX =
            "e0be60e06b8236241ebbf304e3dccd0f26d726a318104f347d36e31af34bf46e";

    // Vector 2: hashToCurveX25519("test", DST) — arbitrary second vector
    private static final String VEC2_HEX =
            "bc3e919bbb3dc55eb4697a98bd7ef48008d5acf7854f585ee2ab2faf3e5cf76c";

    @Test
    void testVector1EmptyMsg() {
        byte[] result = Curve25519Elligator2.hashToCurveX25519(new byte[0], DST);
        assertEquals(VEC1_HEX, toHex(result), "vector 1 (empty msg) mismatch");
    }

    @Test
    void testVector2TestMsg() {
        byte[] result = Curve25519Elligator2.hashToCurveX25519(
                "test".getBytes(StandardCharsets.US_ASCII), DST);
        assertEquals(VEC2_HEX, toHex(result), "vector 2 ('test' msg) mismatch");
    }

    @Test
    void testOutputAlwaysExactly32Bytes() {
        assertEquals(32, Curve25519Elligator2.hashToCurveX25519(new byte[0], DST).length);
        assertEquals(32, Curve25519Elligator2.hashToCurveX25519(
                "test".getBytes(StandardCharsets.US_ASCII), DST).length);
    }

    @Test
    void testMapToCurveElligator2ZeroInput() {
        // u=0: tv1=0, tv2=0, denom=1 (normal path, not the special case).
        // x1 = -A * inv(1) = -A ≡ P-A (mod p).
        // gx1 = x1^3 + A*x1^2 + x1 = (-A)^3 + A*A^2 + (-A) = -A^3 + A^3 - A = -A ≡ P-A (mod p).
        // P-A is a non-residue (Euler criterion = p-1), so the x2 branch fires:
        //   x2 = -A - x1 = -A - (P-A) = -P ≡ 0 (mod p).
        BigInteger result = Curve25519Elligator2.mapToCurveElligator2(BigInteger.ZERO);
        assertEquals(BigInteger.ZERO, result,
                "mapToCurveElligator2(0) should return 0 (x2 branch: -A - (P-A) mod p = 0)");
    }

    @Test
    void testIsSquareGFpKnownSquare() {
        // 4 = 2^2 is always a quadratic residue
        assertTrue(Curve25519Elligator2.isSquareGFp(BigInteger.valueOf(4)),
                "4 must be a quadratic residue mod p");
    }

    @Test
    void testIsSquareGFpKnownNonSquare() {
        // 2 is a non-residue mod 2^255-19 (confirmed by Euler criterion: 2^((p-1)/2) = p-1)
        assertFalse(Curve25519Elligator2.isSquareGFp(BigInteger.valueOf(2)),
                "2 must be a non-residue mod 2^255-19");
    }

    @Test
    void testIsSquareGFpZero() {
        // 0 is considered a square (trivial case)
        assertTrue(Curve25519Elligator2.isSquareGFp(BigInteger.ZERO),
                "0 must be treated as a square");
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
