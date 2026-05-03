// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import java.util.Arrays;

// The "first message" prekey envelope: everything the responder needs to derive the shared key.
// Wire encoding is deferred to Wave D6; this is a pure data holder.
public final class PrekeyEnvelope {

    public final byte[] ephemeralPub;   // 32 bytes — initiator's ephemeral X25519 pub
    public final byte[] kemCiphertext;  // 1088 bytes — ML-KEM-768 ciphertext for responder
    public final int kemKeyId;          // which of the responder's KEM pre-keys was used
    public final int opkId;             // which OPK was consumed (0 == none)
    public final byte[] dcMarshal;      // initiator's own DC (responder verifies AIK)
    public final byte[] aikEd25519Pub;  // initiator's AIK Ed25519 pub (32 bytes)
    public final byte[] aikMldsaPub;    // initiator's AIK ML-DSA-65 pub (1952 bytes)

    public PrekeyEnvelope(
            byte[] ephemeralPub,
            byte[] kemCiphertext,
            int kemKeyId,
            int opkId,
            byte[] dcMarshal,
            byte[] aikEd25519Pub,
            byte[] aikMldsaPub) {
        if (ephemeralPub == null || ephemeralPub.length != 32) {
            throw new IllegalArgumentException("ephemeralPub must be 32 bytes");
        }
        if (kemCiphertext == null || kemCiphertext.length == 0) {
            throw new IllegalArgumentException("kemCiphertext must not be empty");
        }
        this.ephemeralPub = Arrays.copyOf(ephemeralPub, 32);
        this.kemCiphertext = Arrays.copyOf(kemCiphertext, kemCiphertext.length);
        this.kemKeyId = kemKeyId;
        this.opkId = opkId;
        this.dcMarshal = dcMarshal != null ? Arrays.copyOf(dcMarshal, dcMarshal.length) : null;
        this.aikEd25519Pub = aikEd25519Pub != null
                ? Arrays.copyOf(aikEd25519Pub, aikEd25519Pub.length) : null;
        this.aikMldsaPub = aikMldsaPub != null
                ? Arrays.copyOf(aikMldsaPub, aikMldsaPub.length) : null;
    }
}
