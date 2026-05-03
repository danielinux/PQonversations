// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import java.util.Arrays;

// Immutable result of a PQXDH session establishment (initiator or responder).
// rootKey and initialChainKey are 32 bytes each; ad is 64 bytes.
// The 64-byte HKDF output is split: [0:32] = rootKey, [32:64] = initialChainKey.
// Initiator assigns initialChainKey as its send chain; responder assigns it as recv chain.
public final class PqxdhResult {

    public enum Role { INITIATOR, RESPONDER }

    private final Role role;
    private final byte[] rootKey;           // 32 bytes
    private final byte[] initialChainKey;   // 32 bytes (send for initiator, recv for responder)
    private final byte[] ad;                // 64 bytes: initiator_dik_x25519 || responder_dik_x25519
    private final PrekeyEnvelope envelope;  // non-null on INITIATOR side; null on RESPONDER

    public PqxdhResult(
            Role role,
            byte[] rootKey,
            byte[] initialChainKey,
            byte[] ad,
            PrekeyEnvelope envelope) {
        if (rootKey == null || rootKey.length != 32) {
            throw new IllegalArgumentException("rootKey must be 32 bytes");
        }
        if (initialChainKey == null || initialChainKey.length != 32) {
            throw new IllegalArgumentException("initialChainKey must be 32 bytes");
        }
        if (ad == null || ad.length != 64) {
            throw new IllegalArgumentException("ad must be 64 bytes");
        }
        this.role = role;
        this.rootKey = Arrays.copyOf(rootKey, 32);
        this.initialChainKey = Arrays.copyOf(initialChainKey, 32);
        this.ad = Arrays.copyOf(ad, 64);
        this.envelope = envelope;
    }

    public Role getRole() { return role; }

    public byte[] getRootKey() { return Arrays.copyOf(rootKey, 32); }

    // For INITIATOR: initial send chain key.  For RESPONDER: initial recv chain key.
    public byte[] getInitialChainKey() { return Arrays.copyOf(initialChainKey, 32); }

    public byte[] getAd() { return Arrays.copyOf(ad, 64); }

    // Non-null only on the INITIATOR side; the envelope is sent to the responder.
    public PrekeyEnvelope getEnvelope() { return envelope; }
}
