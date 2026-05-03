// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

// Mutable Megolm-style sender chain state. Not wire-serialised in B3;
// session-local only. Max 256 skipped keys (DEFAULT_MAX_SKIPPED).
public final class SenderChain {

    public static final int DEFAULT_MAX_SKIPPED = 256;

    public final int epoch;
    public byte[] chainKey;    // 32 bytes; mutated on each step
    public int nextIndex;

    // Maps chain index → message key for out-of-order delivery.
    private final Map<Integer, byte[]> skipped = new HashMap<>();

    public SenderChain(int epoch, byte[] chainKey) {
        if (chainKey == null || chainKey.length != 32) {
            throw new IllegalArgumentException("SenderChain: chainKey must be 32 bytes");
        }
        this.epoch     = epoch;
        this.chainKey  = Arrays.copyOf(chainKey, 32);
        this.nextIndex = 0;
    }

    // Advance the chain one step.
    // MK = HMAC(CK, 0x01), CK_next = HMAC(CK, 0x02).
    // Returns MK; updates chainKey and nextIndex.
    public byte[] step(HmacSha256 mac) {
        byte[] mk      = mac.mac(chainKey, new byte[]{0x01});
        byte[] nextCK  = mac.mac(chainKey, new byte[]{0x02});
        chainKey = nextCK;
        nextIndex++;
        return mk;
    }

    // Pop a skipped message key by index; returns null if absent.
    public byte[] consumeSkipped(int index) {
        return skipped.remove(index);
    }

    // Store a skipped message key. Throws if the table would exceed 256 entries.
    public void putSkipped(int index, byte[] key) {
        if (skipped.size() >= DEFAULT_MAX_SKIPPED) {
            throw new IllegalStateException("SenderChain: skipped-key table full (max 256)");
        }
        skipped.put(index, Arrays.copyOf(key, key.length));
    }

    // Static helper for callers that need (mk, nextCK) without mutating state.
    public static byte[][] chainStep(byte[] ck, HmacSha256 mac) {
        byte[] mk     = mac.mac(ck, new byte[]{0x01});
        byte[] nextCK = mac.mac(ck, new byte[]{0x02});
        return new byte[][]{mk, nextCK};
    }
}
