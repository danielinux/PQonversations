// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

import java.util.Arrays;

// Raw-byte KEM key pair; holds ML-KEM encoded private and public key bytes.
public final class KemKeyPair {

    public final byte[] priv;
    public final byte[] pub;

    public KemKeyPair(byte[] priv, byte[] pub) {
        // Defensive copies so callers cannot mutate our internals.
        this.priv = Arrays.copyOf(priv, priv.length);
        this.pub  = Arrays.copyOf(pub,  pub.length);
    }
}
