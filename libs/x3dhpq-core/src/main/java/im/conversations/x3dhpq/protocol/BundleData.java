// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

// Immutable plain-Java view of a peer bundle, stripped of XML. Android-XML-free.
// The fromXml parser lives in the app package (eu.siacs.conversations.crypto.x3dhpq.protocol)
// because it references the Conversations Extension model.
public final class BundleData {

    // A single KEM pre-key (id + 1184-byte ML-KEM-768 public key) plus the
    // hybrid DIK signature over the public key (spec §9.1). sigEd/sigMldsa may be
    // null when the bundle omitted them; the receiver rejects such a key.
    public static final class KemPreKey {
        public final int id;
        public final byte[] pub; // 1184 bytes
        public final byte[] sigEd;    // 64  (DIK Ed25519 sig over pub), nullable
        public final byte[] sigMldsa; // 3309 (DIK ML-DSA-65 sig over pub), nullable

        public KemPreKey(int id, byte[] pub) {
            this(id, pub, null, null);
        }

        public KemPreKey(int id, byte[] pub, byte[] sigEd, byte[] sigMldsa) {
            if (pub == null || pub.length == 0) throw new IllegalArgumentException("kem pub empty");
            this.id = id;
            this.pub = Arrays.copyOf(pub, pub.length);
            this.sigEd = sigEd != null ? Arrays.copyOf(sigEd, sigEd.length) : null;
            this.sigMldsa = sigMldsa != null ? Arrays.copyOf(sigMldsa, sigMldsa.length) : null;
        }
    }

    // A single one-time pre-key (id + 32-byte X25519 public key).
    public static final class OneTimePreKey {
        public final int id;
        public final byte[] pub; // 32 bytes

        public OneTimePreKey(int id, byte[] pub) {
            if (pub == null || pub.length != 32) {
                throw new IllegalArgumentException("opk pub must be 32 bytes");
            }
            this.id = id;
            this.pub = Arrays.copyOf(pub, 32);
        }
    }

    public final byte[] aikEd25519Pub;   // 32
    public final byte[] aikMldsaPub;     // 1952
    public final byte[] dcMarshal;       // variable
    public final byte[] dikEd25519Pub;   // 32
    public final byte[] dikX25519Pub;    // 32 (the "ik" in X3DH)
    public final byte[] dikMldsaPub;     // 1952
    public final int spkId;
    public final byte[] spkPub;          // 32
    public final byte[] spkSig;          // 64 (Ed25519 sig over SPK)
    public final List<KemPreKey> kemPreKeys;
    public final List<OneTimePreKey> opks;

    public BundleData(
            byte[] aikEd25519Pub,
            byte[] aikMldsaPub,
            byte[] dcMarshal,
            byte[] dikEd25519Pub,
            byte[] dikX25519Pub,
            byte[] dikMldsaPub,
            int spkId,
            byte[] spkPub,
            byte[] spkSig,
            List<KemPreKey> kemPreKeys,
            List<OneTimePreKey> opks) {
        this.aikEd25519Pub = aikEd25519Pub != null ? Arrays.copyOf(aikEd25519Pub, aikEd25519Pub.length) : null;
        this.aikMldsaPub = aikMldsaPub != null ? Arrays.copyOf(aikMldsaPub, aikMldsaPub.length) : null;
        this.dcMarshal = dcMarshal != null ? Arrays.copyOf(dcMarshal, dcMarshal.length) : null;
        this.dikEd25519Pub = dikEd25519Pub != null ? Arrays.copyOf(dikEd25519Pub, dikEd25519Pub.length) : null;
        this.dikX25519Pub = dikX25519Pub != null ? Arrays.copyOf(dikX25519Pub, dikX25519Pub.length) : null;
        this.dikMldsaPub = dikMldsaPub != null ? Arrays.copyOf(dikMldsaPub, dikMldsaPub.length) : null;
        this.spkId = spkId;
        this.spkPub = spkPub != null ? Arrays.copyOf(spkPub, spkPub.length) : null;
        this.spkSig = spkSig != null ? Arrays.copyOf(spkSig, spkSig.length) : null;
        this.kemPreKeys = kemPreKeys != null
                ? Collections.unmodifiableList(new ArrayList<>(kemPreKeys))
                : Collections.emptyList();
        this.opks = opks != null
                ? Collections.unmodifiableList(new ArrayList<>(opks))
                : Collections.emptyList();
    }
}
