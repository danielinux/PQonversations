// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.HkdfSha512;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// Performs PQXDH key agreement as the responder (Bob).
// Mirrors Go's RespondSession in x3dhpqcrypto/x3dh.go.
// Chain-key assignment is inverted versus the initiator:
//   okm[32:64] = initialChainKey for the RESPONDER (= initiator's send, responder's recv).
public final class PqxdhResponder {

    // Must match PqxdhInitiator.INFO_X3DH exactly.
    private static final byte[] INFO_X3DH =
            "X3DHPQ-X3DH-PQ-v0".getBytes(StandardCharsets.UTF_8);

    // 64-byte zero salt to match Go's hkdf64(nil, ...).
    private static final byte[] ZERO_SALT_64 = new byte[64];

    private PqxdhResponder() {}

    /**
     * Derives the shared session keys from the initiator's prekey envelope.
     *
     * @param mySpkPriv          local SPK private key (32 bytes)
     * @param myDikX25519Priv    local DIK X25519 private key (32 bytes)
     * @param myDikX25519Pub     local DIK X25519 public key (32 bytes)
     * @param myKemPriv          ML-KEM-768 private key for the KEM pre-key chosen by initiator
     * @param myOpkPriv          OPK private key if initiator chose one; null otherwise
     * @param peerDikX25519Pub   initiator's DIK X25519 public key (from envelope / DC)
     * @param peerEphPub         initiator's ephemeral X25519 public key (from envelope, 32 bytes)
     * @param kemCiphertext      KEM ciphertext from the initiator (1088 bytes)
     * @param hkdf               HKDF-SHA-512 implementation
     * @return PqxdhResult with role=RESPONDER; envelope is null
     */
    public static PqxdhResult respond(
            byte[] mySpkPriv,
            byte[] myDikX25519Priv,
            byte[] myDikX25519Pub,
            byte[] myKemPriv,
            byte[] myOpkPriv,
            byte[] peerDikX25519Pub,
            byte[] peerEphPub,
            byte[] kemCiphertext,
            HkdfSha512 hkdf) {

        // Step 1: DH components (mirrors initiator's order exactly).
        // dh1 = X25519(mySpkPriv, peerDikX25519Pub)   == initiator's dh1
        byte[] dh1 = X3dhpqCrypto.x25519SharedSecret(mySpkPriv, peerDikX25519Pub);
        // dh2 = X25519(myDikX25519Priv, peerEphPub)   == initiator's dh2
        byte[] dh2 = X3dhpqCrypto.x25519SharedSecret(myDikX25519Priv, peerEphPub);
        // dh3 = X25519(mySpkPriv, peerEphPub)         == initiator's dh3
        byte[] dh3 = X3dhpqCrypto.x25519SharedSecret(mySpkPriv, peerEphPub);

        // Step 2: KEM decapsulation.
        byte[] kemSS = X3dhpqCrypto.mlkem768Decaps(myKemPriv, kemCiphertext);

        // Step 3: assemble IKM.
        int ikmLen = 32 + 32 + 32 + (myOpkPriv != null ? 32 : 0) + 32;
        byte[] ikm = new byte[ikmLen];
        int pos = 0;
        System.arraycopy(dh1, 0, ikm, pos, 32); pos += 32;
        System.arraycopy(dh2, 0, ikm, pos, 32); pos += 32;
        System.arraycopy(dh3, 0, ikm, pos, 32); pos += 32;
        if (myOpkPriv != null) {
            // dh4 = X25519(myOpkPriv, peerEphPub)     == initiator's dh4
            byte[] dh4 = X3dhpqCrypto.x25519SharedSecret(myOpkPriv, peerEphPub);
            System.arraycopy(dh4, 0, ikm, pos, 32); pos += 32;
            Arrays.fill(dh4, (byte) 0);
        }
        System.arraycopy(kemSS, 0, ikm, pos, 32);

        // Step 4: HKDF-SHA-512(salt=zeros[64], ikm, info="X3DHPQ-X3DH-PQ-v0", length=64).
        byte[] okm = hkdf.derive(ZERO_SALT_64, ikm, INFO_X3DH, 64);

        // Step 5: split — [0:32] rootKey, [32:64] initialChainKey.
        // For the RESPONDER this is the recv chain (=initiator's send chain), so the two sides
        // use getInitialChainKey() symmetrically: initiator sends, responder receives.
        byte[] rootKey = new byte[32];
        byte[] initRecvCK = new byte[32];
        System.arraycopy(okm, 0, rootKey, 0, 32);
        System.arraycopy(okm, 32, initRecvCK, 0, 32);

        // Step 6: AD = peerDikX25519Pub || myDikX25519Pub (mirrors initiator: init_pub || resp_pub).
        byte[] ad = new byte[64];
        System.arraycopy(peerDikX25519Pub, 0, ad, 0, 32);
        System.arraycopy(myDikX25519Pub, 0, ad, 32, 32);

        // Wipe intermediate material.
        Arrays.fill(dh1, (byte) 0);
        Arrays.fill(dh2, (byte) 0);
        Arrays.fill(dh3, (byte) 0);
        Arrays.fill(kemSS, (byte) 0);
        Arrays.fill(ikm, (byte) 0);

        // envelope is null on the responder side (no data to send back in this wave).
        return new PqxdhResult(PqxdhResult.Role.RESPONDER, rootKey, initRecvCK, ad, null);
    }
}
