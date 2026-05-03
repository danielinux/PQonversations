// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

import java.util.Arrays;

// Result of a KEM encapsulation: 32-byte shared secret + 1088-byte ciphertext (ML-KEM-768).
public final class KemEncapsulation {

    public final byte[] sharedSecret; // 32 bytes for ML-KEM-768
    public final byte[] ciphertext;   // 1088 bytes for ML-KEM-768

    public KemEncapsulation(byte[] sharedSecret, byte[] ciphertext) {
        // Defensive copies so callers cannot mutate our internals.
        this.sharedSecret = Arrays.copyOf(sharedSecret, sharedSecret.length);
        this.ciphertext   = Arrays.copyOf(ciphertext,   ciphertext.length);
    }
}
