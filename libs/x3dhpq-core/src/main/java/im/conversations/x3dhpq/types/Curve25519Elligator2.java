// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.math.BigInteger;

// curve25519_XMD:SHA-512_ELL2_NU_ per RFC 9380 §6.7.1 + §6.7.2.
// Non-constant-time field arithmetic is acceptable: the input to H2C is already
// hashed from public transcript context, so timing observations reveal nothing
// beyond what a passive network observer sees.
// Mirrors hashToCurveX25519() / mapToCurveElligator2() from elligator2.go byte-for-byte.
public final class Curve25519Elligator2 {

    private Curve25519Elligator2() {}

    // Field prime p = 2^255 - 19
    private static final BigInteger P =
            BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));

    // (p - 1) / 2  — used for Euler's criterion
    private static final BigInteger P_MINUS_1_OVER_2 =
            P.subtract(BigInteger.ONE).shiftRight(1);

    // Curve25519 Montgomery coefficient A = 486662
    private static final BigInteger A = BigInteger.valueOf(486662);

    // Elligator2 constant Z = 2
    private static final BigInteger Z = BigInteger.TWO;

    /**
     * curve25519_XMD:SHA-512_ELL2_NU_ per RFC 9380 §6.7.2.
     * Returns the 32-byte little-endian X25519-wire-format point.
     */
    public static byte[] hashToCurveX25519(byte[] msg, byte[] dst) {
        byte[] uBytes = ExpandMessageXmd.expand(msg, dst, 48);
        BigInteger u = bytesToFieldElement(uBytes);
        BigInteger x = mapToCurveElligator2(u);

        // Encode as 32-byte little-endian X25519 wire format.
        // BigInteger.toByteArray() is big-endian and may prepend a 0x00 sign byte.
        // Mirror Go lines 156–164: iterate xBytes from last index to 0, copying into out.
        byte[] xBytes = x.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < xBytes.length; i++) {
            if (i >= 32) {
                break;
            }
            // xBytes[len-1-i] is the least-significant byte at position i
            out[i] = xBytes[xBytes.length - 1 - i];
        }
        return out;
    }

    /**
     * RFC 9380 §6.7.1 map_to_curve_elligator2_curve25519.
     * A = 486662, Z = 2.
     */
    static BigInteger mapToCurveElligator2(BigInteger u) {
        BigInteger tv1 = u.multiply(u).mod(P);
        BigInteger tv2 = Z.multiply(tv1).mod(P);

        // denom = 1 + Z*u^2
        BigInteger denom = BigInteger.ONE.add(tv2).mod(P);

        BigInteger x1;
        if (denom.equals(BigInteger.ZERO)) {
            // Special case per RFC 9380: if 1 + Z*u^2 == 0, x1 = A
            x1 = A;
        } else {
            // x1 = (-A) * inv(1 + Z*u^2) mod p
            BigInteger negA = A.negate().mod(P);
            x1 = negA.multiply(denom.modInverse(P)).mod(P);
        }

        // gx1 = x1^3 + A*x1^2 + x1
        BigInteger x1sq = x1.multiply(x1).mod(P);
        BigInteger gx1 = x1sq.multiply(x1).mod(P);
        BigInteger t = A.multiply(x1sq).mod(P);
        gx1 = gx1.add(t).add(x1).mod(P);

        if (isSquareGFp(gx1)) {
            return x1;
        } else {
            // x2 = -A - x1
            return A.negate().subtract(x1).mod(P);
        }
    }

    /**
     * Euler's criterion: u^((p-1)/2) mod p.
     * Returns true iff u is 0 (trivial square) or a quadratic residue mod p.
     */
    static boolean isSquareGFp(BigInteger u) {
        BigInteger e = u.modPow(P_MINUS_1_OVER_2, P);
        return e.equals(BigInteger.ZERO) || e.equals(BigInteger.ONE);
    }

    /**
     * RFC 9380 §4 OS2IP: left-pad b to 48 bytes (big-endian), then reduce mod p.
     */
    static BigInteger bytesToFieldElement(byte[] b) {
        byte[] padded = new byte[48];
        System.arraycopy(b, Math.max(0, b.length - 48), padded, Math.max(0, 48 - b.length),
                Math.min(b.length, 48));
        return new BigInteger(1, padded).mod(P);
    }
}
