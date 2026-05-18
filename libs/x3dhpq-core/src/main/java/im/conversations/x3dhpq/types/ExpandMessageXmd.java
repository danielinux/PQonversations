// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

// RFC 9380 §5.4.1 expand_message_xmd with H = SHA-512.
// Fixed parameters: b_in_bytes = 64, s_in_bytes = 128.
// Mirrors expandMessageXMDSHA512() from elligator2.go byte-for-byte.
public final class ExpandMessageXmd {

    private static final int B_IN_BYTES = 64;
    private static final int S_IN_BYTES = 128;

    private ExpandMessageXmd() {}

    public static byte[] expand(byte[] msg, byte[] dst, int lenInBytes) {
        int ell = (lenInBytes + B_IN_BYTES - 1) / B_IN_BYTES;
        if (ell > 255 || lenInBytes > 65535 || dst.length > 255) {
            throw new IllegalArgumentException(
                    "expand_message_xmd: invalid parameter (ell=" + ell
                    + ", lenInBytes=" + lenInBytes + ", dst.length=" + dst.length + ")");
        }

        // DST_prime = DST || I2OSP(len(DST), 1)
        byte[] dstPrime = new byte[dst.length + 1];
        System.arraycopy(dst, 0, dstPrime, 0, dst.length);
        dstPrime[dst.length] = (byte) dst.length;

        // Z_pad = 0x00 * s_in_bytes
        byte[] zPad = new byte[S_IN_BYTES];

        // l_i_b_str = I2OSP(lenInBytes, 2)
        byte[] liBStr = new byte[]{(byte) (lenInBytes >> 8), (byte) lenInBytes};

        // msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        byte[] b0 = sha512(concat(zPad, msg, liBStr, new byte[]{0x00}, dstPrime));

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        byte[] b1 = sha512(concat(b0, new byte[]{0x01}, dstPrime));

        byte[] pseudoRandom = new byte[ell * B_IN_BYTES];
        System.arraycopy(b1, 0, pseudoRandom, 0, B_IN_BYTES);

        byte[] prev = b1;
        for (int i = 2; i <= ell; i++) {
            // b_i = H((b_0 XOR b_{i-1}) || I2OSP(i, 1) || DST_prime)
            byte[] xored = new byte[B_IN_BYTES];
            for (int j = 0; j < B_IN_BYTES; j++) {
                xored[j] = (byte) (b0[j] ^ prev[j]);
            }
            byte[] bi = sha512(concat(xored, new byte[]{(byte) i}, dstPrime));
            System.arraycopy(bi, 0, pseudoRandom, (i - 1) * B_IN_BYTES, B_IN_BYTES);
            prev = bi;
        }

        byte[] out = new byte[lenInBytes];
        System.arraycopy(pseudoRandom, 0, out, 0, lenInBytes);
        return out;
    }

    private static byte[] sha512(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("SHA-512 unavailable", e);
        }
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
