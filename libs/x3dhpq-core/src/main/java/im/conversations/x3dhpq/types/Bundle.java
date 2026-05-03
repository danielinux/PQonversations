// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Immutable container for the public side of a device's X3DHPQ bundle.
 *
 * Mirrors Go's PublicBundle in bundle.go.
 *
 * NOTE: The Go reference does NOT define a binary Marshal() method for PublicBundle
 * (it is published as XML via the XEP stanza format).  Binary marshal/unmarshal is
 * therefore intentionally absent here; it will be added as part of Wave C when the
 * XML representation is wired up.  This class is a plain in-memory container.
 */
public final class Bundle {

    // --- Inner types ---

    /** Public signed pre-key: X25519 public key + Ed25519 signature over (uint32(id) || pub). */
    public static final class PublicSignedPreKey {
        final int id;           // uint32
        final byte[] pubX25519; // 32 bytes
        final byte[] signature; // Ed25519 signature, 64 bytes

        public PublicSignedPreKey(int id, byte[] pubX25519, byte[] signature) {
            if (pubX25519 == null || pubX25519.length != 32) {
                throw new IllegalArgumentException("pubX25519 must be 32 bytes");
            }
            this.id        = id;
            this.pubX25519 = Arrays.copyOf(pubX25519, 32);
            this.signature = signature != null ? Arrays.copyOf(signature, signature.length) : new byte[0];
        }

        public int getId()           { return id; }
        public byte[] getPubX25519() { return Arrays.copyOf(pubX25519, 32); }
        public byte[] getSignature() { return Arrays.copyOf(signature, signature.length); }
    }

    /** Public KEM pre-key: ML-KEM-768 public key (1184 bytes per NIST spec). */
    public static final class PublicKEMPreKey {
        final int id;          // uint32
        final byte[] pubMLKEM; // 1184 bytes for ML-KEM-768

        public PublicKEMPreKey(int id, byte[] pubMLKEM) {
            if (pubMLKEM == null || pubMLKEM.length == 0) {
                throw new IllegalArgumentException("pubMLKEM must not be empty");
            }
            this.id       = id;
            this.pubMLKEM = Arrays.copyOf(pubMLKEM, pubMLKEM.length);
        }

        public int getId()          { return id; }
        public byte[] getPubMLKEM() { return Arrays.copyOf(pubMLKEM, pubMLKEM.length); }
    }

    /** Public one-time pre-key: X25519 public key. */
    public static final class PublicOneTimePreKey {
        final int id;           // uint32
        final byte[] pubX25519; // 32 bytes

        public PublicOneTimePreKey(int id, byte[] pubX25519) {
            if (pubX25519 == null || pubX25519.length != 32) {
                throw new IllegalArgumentException("pubX25519 must be 32 bytes");
            }
            this.id        = id;
            this.pubX25519 = Arrays.copyOf(pubX25519, 32);
        }

        public int getId()           { return id; }
        public byte[] getPubX25519() { return Arrays.copyOf(pubX25519, 32); }
    }

    // --- Bundle fields ---

    final AccountIdentityPub aikPub;     // may be null if AIK not present
    final DeviceCertificate deviceCert;
    final PublicSignedPreKey signedPreKey;
    final List<PublicKEMPreKey> kemPreKeys;       // >= 5 per spec §9.1
    final List<PublicOneTimePreKey> oneTimePreKeys; // >= 10 per spec §9.1

    public Bundle(
            AccountIdentityPub aikPub,
            DeviceCertificate deviceCert,
            PublicSignedPreKey signedPreKey,
            List<PublicKEMPreKey> kemPreKeys,
            List<PublicOneTimePreKey> oneTimePreKeys) {
        if (deviceCert == null)   throw new IllegalArgumentException("deviceCert must not be null");
        if (signedPreKey == null) throw new IllegalArgumentException("signedPreKey must not be null");
        this.aikPub        = aikPub;
        this.deviceCert    = deviceCert;
        this.signedPreKey  = signedPreKey;
        this.kemPreKeys    = kemPreKeys != null
                ? Collections.unmodifiableList(new ArrayList<>(kemPreKeys))
                : Collections.emptyList();
        this.oneTimePreKeys = oneTimePreKeys != null
                ? Collections.unmodifiableList(new ArrayList<>(oneTimePreKeys))
                : Collections.emptyList();
    }

    public AccountIdentityPub getAikPub()                      { return aikPub; }
    public DeviceCertificate getDeviceCert()                   { return deviceCert; }
    public PublicSignedPreKey getSignedPreKey()                 { return signedPreKey; }
    public List<PublicKEMPreKey> getKemPreKeys()               { return kemPreKeys; }
    public List<PublicOneTimePreKey> getOneTimePreKeys()        { return oneTimePreKeys; }
}
