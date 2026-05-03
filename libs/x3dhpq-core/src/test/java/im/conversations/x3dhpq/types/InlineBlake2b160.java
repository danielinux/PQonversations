// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal BLAKE2b-160 implementation per RFC 7693. Test use only — production uses wolfJCE/BouncyCastle.
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.types.Blake2b160;

// Package-private; instantiate directly in tests.
class InlineBlake2b160 implements Blake2b160 {

    // BLAKE2b initialisation vector (first 8 fractional words of sqrt primes, RFC 7693 §2.6)
    private static final long[] IV = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
        0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
        0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    // Sigma permutation table (RFC 7693 §2.7)
    private static final int[][] SIGMA = {
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
        {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
        {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
        {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
        {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
        {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
        {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
        {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
        {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
        {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
        {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3}
    };

    @Override
    public byte[] hash(byte[] input) {
        return blake2b160(input);
    }

    static byte[] blake2b160(byte[] input) {
        // digest length = 20 (160 bits)
        final int digestLen = 20;
        // h = IV, h[0] xor param block (digest len | key len=0 | fanout=1 | depth=1)
        long[] h = IV.clone();
        h[0] ^= 0x01010000L | digestLen; // param block: digest=20, key=0, fanout=1, depth=1

        // Process input in 128-byte blocks
        int inputLen = (input == null) ? 0 : input.length;
        byte[] msg = (input == null) ? new byte[0] : input;

        // Counter tracks bytes consumed so far (as a 128-bit little-endian int; we only need 64 bits for sane inputs)
        long byteCount = 0;

        int offset = 0;
        byte[] block = new byte[128];

        if (inputLen == 0) {
            // empty message: one final block of all zeros, counter=0
            compress(h, block, 0, true);
        } else {
            while (offset < inputLen) {
                int remaining = inputLen - offset;
                boolean last = remaining <= 128;
                int take = last ? remaining : 128;
                // fill block
                java.util.Arrays.fill(block, (byte) 0);
                System.arraycopy(msg, offset, block, 0, take);
                offset += take;
                byteCount += take;
                compress(h, block, byteCount, last);
            }
        }

        // Extract digest (little-endian 64-bit words)
        byte[] out = new byte[digestLen];
        for (int i = 0; i < (digestLen + 7) / 8; i++) {
            long word = h[i];
            for (int j = 0; j < 8 && i * 8 + j < digestLen; j++) {
                out[i * 8 + j] = (byte) (word >>> (j * 8));
            }
        }
        return out;
    }

    private static void compress(long[] h, byte[] block, long counter, boolean last) {
        // Initialise working variables
        long v0 = h[0], v1 = h[1], v2 = h[2], v3 = h[3];
        long v4 = h[4], v5 = h[5], v6 = h[6], v7 = h[7];
        long v8  = IV[0], v9  = IV[1], v10 = IV[2], v11 = IV[3];
        long v12 = IV[4] ^ counter;          // low 64 bits of byte count
        long v13 = IV[5];                    // high 64 bits (zero for inputs < 2^64 bytes)
        long v14 = last ? ~IV[6] : IV[6];   // invert if last block
        long v15 = IV[7];

        // Decode block as 16 little-endian 64-bit words
        long[] m = new long[16];
        for (int i = 0; i < 16; i++) {
            int base = i * 8;
            m[i] = (block[base]     & 0xffL)
                 | ((block[base+1] & 0xffL) << 8)
                 | ((block[base+2] & 0xffL) << 16)
                 | ((block[base+3] & 0xffL) << 24)
                 | ((block[base+4] & 0xffL) << 32)
                 | ((block[base+5] & 0xffL) << 40)
                 | ((block[base+6] & 0xffL) << 48)
                 | ((block[base+7] & 0xffL) << 56);
        }

        // 12 rounds of mixing
        long[] v = {v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15};
        for (int r = 0; r < 12; r++) {
            int[] s = SIGMA[r];
            v = G(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
            v = G(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
            v = G(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
            v = G(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
            v = G(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
            v = G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            v = G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
            v = G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
        }

        // XOR in both halves
        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    // G mixing function (RFC 7693 §3.1)
    private static long[] G(long[] v, int a, int b, int c, int d, long x, long y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
        return v;
    }
}
