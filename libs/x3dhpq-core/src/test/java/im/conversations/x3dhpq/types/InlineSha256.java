// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal SHA-256 implementation for test use only. Production uses wolfJCE.
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.types.Sha256;

class InlineSha256 implements Sha256 {

    @Override
    public byte[] hash(byte[] input) {
        return sha256(input);
    }

    // SHA-256 constants
    private static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static byte[] sha256(byte[] input) {
        if (input == null) input = new byte[0];
        long bitLen = (long) input.length * 8;

        // pad: append 0x80, zeros, then 8-byte big-endian bit length (total length % 64 == 56)
        int padLen = (55 - input.length % 64 + 64) % 64 + 1; // bytes of 0x80 + zeros
        byte[] msg = new byte[input.length + padLen + 8];
        System.arraycopy(input, 0, msg, 0, input.length);
        msg[input.length] = (byte) 0x80;
        // big-endian bit length at end
        for (int i = 7; i >= 0; i--) {
            msg[msg.length - 8 + i] = (byte) (bitLen & 0xff);
            bitLen >>>= 8;
        }

        // initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
        int h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        int h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

        for (int i = 0; i < msg.length; i += 64) {
            int[] w = new int[64];
            for (int j = 0; j < 16; j++) {
                int base = i + j * 4;
                w[j] = ((msg[base] & 0xff) << 24)
                        | ((msg[base+1] & 0xff) << 16)
                        | ((msg[base+2] & 0xff) << 8)
                        |  (msg[base+3] & 0xff);
            }
            for (int j = 16; j < 64; j++) {
                int s0 = Integer.rotateRight(w[j-15], 7)  ^ Integer.rotateRight(w[j-15], 18) ^ (w[j-15] >>> 3);
                int s1 = Integer.rotateRight(w[j-2],  17) ^ Integer.rotateRight(w[j-2],  19) ^ (w[j-2]  >>> 10);
                w[j] = w[j-16] + s0 + w[j-7] + s1;
            }

            int a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (int j = 0; j < 64; j++) {
                int S1   = Integer.rotateRight(e, 6) ^ Integer.rotateRight(e, 11) ^ Integer.rotateRight(e, 25);
                int ch   = (e & f) ^ (~e & g);
                int temp1 = h + S1 + ch + K[j] + w[j];
                int S0   = Integer.rotateRight(a, 2) ^ Integer.rotateRight(a, 13) ^ Integer.rotateRight(a, 22);
                int maj  = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = S0 + maj;
                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }
            h0 += a; h1 += b; h2 += c; h3 += d;
            h4 += e; h5 += f; h6 += g; h7 += h;
        }

        byte[] digest = new byte[32];
        packInt(h0, digest, 0);  packInt(h1, digest, 4);
        packInt(h2, digest, 8);  packInt(h3, digest, 12);
        packInt(h4, digest, 16); packInt(h5, digest, 20);
        packInt(h6, digest, 24); packInt(h7, digest, 28);
        return digest;
    }

    private static void packInt(int v, byte[] b, int off) {
        b[off]   = (byte) (v >>> 24);
        b[off+1] = (byte) (v >>> 16);
        b[off+2] = (byte) (v >>> 8);
        b[off+3] = (byte) v;
    }
}
