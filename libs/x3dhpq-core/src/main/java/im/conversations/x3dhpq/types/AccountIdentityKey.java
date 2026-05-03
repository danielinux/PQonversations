// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.util.Arrays;

// Holds the private account identity key material; local-storage only, never sent on wire.
public final class AccountIdentityKey {

    // BC Ed25519PrivateKeyParameters.getEncoded() returns the 32-byte seed.
    static final int ED25519_PRIV_SIZE = 32;
    // BC MLDSAPrivateKeyParameters.getEncoded() returns 4032 bytes for ML-DSA-65.
    static final int MLDSA65_PRIV_SIZE = 4032;

    // Total marshal size: privEd25519(32) + privMLDSA(4032) + AccountIdentityPub.marshal()(1987)
    static final int MARSHAL_SIZE = ED25519_PRIV_SIZE + MLDSA65_PRIV_SIZE + 1987;

    private final byte[] privEd25519;
    private final byte[] privMLDSA;
    private final AccountIdentityPub pub;

    public AccountIdentityKey(byte[] privEd25519, byte[] privMLDSA, AccountIdentityPub pub) {
        if (privEd25519 == null || privEd25519.length != ED25519_PRIV_SIZE) {
            throw new IllegalArgumentException("privEd25519 must be 32 bytes");
        }
        if (privMLDSA == null || privMLDSA.length != MLDSA65_PRIV_SIZE) {
            throw new IllegalArgumentException("privMLDSA must be 4032 bytes");
        }
        if (pub == null) {
            throw new IllegalArgumentException("pub must not be null");
        }
        this.privEd25519 = Arrays.copyOf(privEd25519, privEd25519.length);
        this.privMLDSA = Arrays.copyOf(privMLDSA, privMLDSA.length);
        this.pub = pub;
    }

    public byte[] getPrivEd25519() {
        return Arrays.copyOf(privEd25519, privEd25519.length);
    }

    public byte[] getPrivMLDSA() {
        return Arrays.copyOf(privMLDSA, privMLDSA.length);
    }

    public AccountIdentityPub getPublic() {
        return pub;
    }

    /**
     * Serialises to a local-storage blob (never sent on wire).
     * Layout: privEd25519(32) | privMLDSA(4032) | AccountIdentityPub.marshal()(1987) = 6051 bytes.
     */
    public byte[] marshal() {
        byte[] pubBytes = pub.marshal();
        ByteBuffer buf = ByteBuffer.allocate(ED25519_PRIV_SIZE + MLDSA65_PRIV_SIZE + pubBytes.length);
        buf.put(privEd25519);
        buf.put(privMLDSA);
        buf.put(pubBytes);
        return buf.array();
    }

    /**
     * Deserialises from a blob produced by {@link #marshal()}.
     */
    public static AccountIdentityKey unmarshal(byte[] raw) {
        if (raw == null || raw.length < MARSHAL_SIZE) {
            throw new IllegalArgumentException(
                    "AIK blob too short: expected " + MARSHAL_SIZE + ", got " + (raw == null ? 0 : raw.length));
        }
        ByteBuffer buf = ByteBuffer.wrap(raw);
        byte[] privEd = new byte[ED25519_PRIV_SIZE];
        buf.get(privEd);
        byte[] privMldsa = new byte[MLDSA65_PRIV_SIZE];
        buf.get(privMldsa);
        byte[] pubBytes = new byte[raw.length - ED25519_PRIV_SIZE - MLDSA65_PRIV_SIZE];
        buf.get(pubBytes);
        AccountIdentityPub pub = AccountIdentityPub.unmarshal(pubBytes);
        return new AccountIdentityKey(privEd, privMldsa, pub);
    }
}
