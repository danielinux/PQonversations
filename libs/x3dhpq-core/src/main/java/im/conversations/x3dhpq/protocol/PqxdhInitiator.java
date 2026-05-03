// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.KemEncapsulation;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.HkdfSha512;

import java.nio.charset.StandardCharsets;

// Performs PQXDH key agreement as the initiator (Alice).
// Mirrors Go's InitiateSession in x3dhpqcrypto/x3dh.go.
// HKDF uses SHA-512 (64-byte zero salt) to match the wolfcrypt Go reference.
public final class PqxdhInitiator {

    // info string for X3DH HKDF; must match Go's infoX3DH constant byte-for-byte.
    private static final byte[] INFO_X3DH =
            "X3DHPQ-X3DH-PQ-v0".getBytes(StandardCharsets.UTF_8);

    // 64-byte zero salt matches Go's hkdf64(nil, ...) which zero-fills 64 bytes when nil.
    private static final byte[] ZERO_SALT_64 = new byte[64];

    private PqxdhInitiator() {}

    /**
     * Derives the shared session keys with the responder described by {@code peerBundle}.
     *
     * @param myDikX25519Priv  local device identity X25519 private key (32 bytes)
     * @param myDikX25519Pub   local device identity X25519 public key (32 bytes)
     * @param myDikEd25519Pub  local device identity Ed25519 public key (32 bytes); placed in envelope
     * @param myDcMarshal      local device certificate bytes; placed in envelope for responder
     * @param myAikEd25519Pub  local AIK Ed25519 public key; placed in envelope
     * @param myAikMldsaPub    local AIK ML-DSA-65 public key; placed in envelope
     * @param peerBundle       the responder's published bundle
     * @param hkdf             HKDF-SHA-512 implementation
     * @return PqxdhResult with role=INITIATOR; envelope is non-null
     */
    public static PqxdhResult initiate(
            byte[] myDikX25519Priv,
            byte[] myDikX25519Pub,
            byte[] myDikEd25519Pub,
            byte[] myDcMarshal,
            byte[] myAikEd25519Pub,
            byte[] myAikMldsaPub,
            BundleData peerBundle,
            HkdfSha512 hkdf) {

        if (peerBundle.kemPreKeys.isEmpty()) {
            throw new IllegalArgumentException("peer bundle has no KEM pre-keys");
        }

        // Step 1: pick the first KEM pre-key (deterministic for v0).
        BundleData.KemPreKey chosenKem = peerBundle.kemPreKeys.get(0);

        // Step 2: pick the first OPK, or null if none.
        BundleData.OneTimePreKey chosenOpk =
                peerBundle.opks.isEmpty() ? null : peerBundle.opks.get(0);

        // Step 3: generate a fresh ephemeral X25519 keypair.
        KeyPair eph = X3dhpqCrypto.x25519GenerateKeypair();

        // Step 4: KEM encapsulation against the peer's KEM pre-key.
        KemEncapsulation encap = X3dhpqCrypto.mlkem768Encaps(chosenKem.pub);

        // Step 5: DH components (matches Go's x3dh.go order exactly).
        // dh1 = X25519(myDikX25519Priv, peer.spkPub)
        byte[] dh1 = X3dhpqCrypto.x25519SharedSecret(myDikX25519Priv, peerBundle.spkPub);
        // dh2 = X25519(eph.priv, peer.dikX25519Pub)
        byte[] dh2 = X3dhpqCrypto.x25519SharedSecret(eph.priv, peerBundle.dikX25519Pub);
        // dh3 = X25519(eph.priv, peer.spkPub)
        byte[] dh3 = X3dhpqCrypto.x25519SharedSecret(eph.priv, peerBundle.spkPub);

        // Step 6: assemble IKM.
        int ikmLen = 32 + 32 + 32 + (chosenOpk != null ? 32 : 0) + 32;
        byte[] ikm = new byte[ikmLen];
        int pos = 0;
        System.arraycopy(dh1, 0, ikm, pos, 32); pos += 32;
        System.arraycopy(dh2, 0, ikm, pos, 32); pos += 32;
        System.arraycopy(dh3, 0, ikm, pos, 32); pos += 32;
        if (chosenOpk != null) {
            // dh4 = X25519(eph.priv, peer.opk.pub)
            byte[] dh4 = X3dhpqCrypto.x25519SharedSecret(eph.priv, chosenOpk.pub);
            System.arraycopy(dh4, 0, ikm, pos, 32); pos += 32;
        }
        System.arraycopy(encap.sharedSecret, 0, ikm, pos, 32);

        // Step 7: HKDF-SHA-512(salt=zeros[64], ikm, info="X3DHPQ-X3DH-PQ-v0", length=64).
        byte[] okm = hkdf.derive(ZERO_SALT_64, ikm, INFO_X3DH, 64);

        // Step 8: split output — [0:32] rootKey, [32:64] initialChainKey (initiator's send CK).
        byte[] rootKey = new byte[32];
        byte[] initSendCK = new byte[32];
        System.arraycopy(okm, 0, rootKey, 0, 32);
        System.arraycopy(okm, 32, initSendCK, 0, 32);

        // Step 9: AD = myDikX25519Pub || peer.dikX25519Pub (matches Go's ad construction).
        byte[] ad = new byte[64];
        System.arraycopy(myDikX25519Pub, 0, ad, 0, 32);
        System.arraycopy(peerBundle.dikX25519Pub, 0, ad, 32, 32);

        // Step 10: build the prekey envelope the responder needs.
        PrekeyEnvelope envelope = new PrekeyEnvelope(
                eph.pub,
                encap.ciphertext,
                chosenKem.id,
                chosenOpk != null ? chosenOpk.id : 0,
                myDcMarshal,
                myDikEd25519Pub,
                myAikMldsaPub);

        // Wipe intermediate DH material from heap.
        java.util.Arrays.fill(dh1, (byte) 0);
        java.util.Arrays.fill(dh2, (byte) 0);
        java.util.Arrays.fill(dh3, (byte) 0);
        java.util.Arrays.fill(ikm, (byte) 0);

        return new PqxdhResult(PqxdhResult.Role.INITIATOR, rootKey, initSendCK, ad, envelope);
    }
}
