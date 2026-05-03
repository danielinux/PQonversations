// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

import java.util.Arrays;

// Raw-byte key pair; avoids JCE Key wrappers which require provider round-trips.
public final class KeyPair {

    public final byte[] priv;
    public final byte[] pub;

    public KeyPair(byte[] priv, byte[] pub) {
        // Defensive copies so callers cannot mutate our internals.
        this.priv = Arrays.copyOf(priv, priv.length);
        this.pub  = Arrays.copyOf(pub,  pub.length);
    }
}
