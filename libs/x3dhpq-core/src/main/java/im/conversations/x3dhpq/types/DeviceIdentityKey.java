// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.util.Arrays;

// Holds all six components of a device identity key; local-storage only, never sent on wire.
public final class DeviceIdentityKey {

    // BC Ed25519PrivateKeyParameters.getEncoded() returns the 32-byte seed.
    static final int ED25519_PRIV_SIZE = 32;
    static final int ED25519_PUB_SIZE = 32;
    static final int X25519_PRIV_SIZE = 32;
    static final int X25519_PUB_SIZE = 32;
    // BC MLDSAPrivateKeyParameters.getEncoded() returns 4032 bytes for ML-DSA-65.
    static final int MLDSA65_PRIV_SIZE = 4032;
    static final int MLDSA65_PUB_SIZE = 1952;

    // Total marshal size: 32+32+32+32+4032+1952 = 6112 bytes.
    static final int MARSHAL_SIZE =
            ED25519_PRIV_SIZE + ED25519_PUB_SIZE
                    + X25519_PRIV_SIZE + X25519_PUB_SIZE
                    + MLDSA65_PRIV_SIZE + MLDSA65_PUB_SIZE;

    private final byte[] privEd25519;
    private final byte[] pubEd25519;
    private final byte[] privX25519;
    private final byte[] pubX25519;
    private final byte[] privMLDSA;
    private final byte[] pubMLDSA;

    public DeviceIdentityKey(
            byte[] privEd25519,
            byte[] pubEd25519,
            byte[] privX25519,
            byte[] pubX25519,
            byte[] privMLDSA,
            byte[] pubMLDSA) {
        if (privEd25519 == null || privEd25519.length != ED25519_PRIV_SIZE)
            throw new IllegalArgumentException("privEd25519 must be 32 bytes");
        if (pubEd25519 == null || pubEd25519.length != ED25519_PUB_SIZE)
            throw new IllegalArgumentException("pubEd25519 must be 32 bytes");
        if (privX25519 == null || privX25519.length != X25519_PRIV_SIZE)
            throw new IllegalArgumentException("privX25519 must be 32 bytes");
        if (pubX25519 == null || pubX25519.length != X25519_PUB_SIZE)
            throw new IllegalArgumentException("pubX25519 must be 32 bytes");
        if (privMLDSA == null || privMLDSA.length != MLDSA65_PRIV_SIZE)
            throw new IllegalArgumentException("privMLDSA must be 4032 bytes");
        if (pubMLDSA == null || pubMLDSA.length != MLDSA65_PUB_SIZE)
            throw new IllegalArgumentException("pubMLDSA must be 1952 bytes");

        this.privEd25519 = Arrays.copyOf(privEd25519, privEd25519.length);
        this.pubEd25519 = Arrays.copyOf(pubEd25519, pubEd25519.length);
        this.privX25519 = Arrays.copyOf(privX25519, privX25519.length);
        this.pubX25519 = Arrays.copyOf(pubX25519, pubX25519.length);
        this.privMLDSA = Arrays.copyOf(privMLDSA, privMLDSA.length);
        this.pubMLDSA = Arrays.copyOf(pubMLDSA, pubMLDSA.length);
    }

    public byte[] getPrivEd25519() {
        return Arrays.copyOf(privEd25519, privEd25519.length);
    }

    public byte[] getPubEd25519() {
        return Arrays.copyOf(pubEd25519, pubEd25519.length);
    }

    public byte[] getPrivX25519() {
        return Arrays.copyOf(privX25519, privX25519.length);
    }

    public byte[] getPubX25519() {
        return Arrays.copyOf(pubX25519, pubX25519.length);
    }

    public byte[] getPrivMLDSA() {
        return Arrays.copyOf(privMLDSA, privMLDSA.length);
    }

    public byte[] getPubMLDSA() {
        return Arrays.copyOf(pubMLDSA, pubMLDSA.length);
    }

    /**
     * Serialises to a local-storage blob (never sent on wire).
     * Layout: privEd25519(32) | pubEd25519(32) | privX25519(32) | pubX25519(32)
     *       | privMLDSA(4032) | pubMLDSA(1952) = 6112 bytes total.
     */
    public byte[] marshal() {
        ByteBuffer buf = ByteBuffer.allocate(MARSHAL_SIZE);
        buf.put(privEd25519);
        buf.put(pubEd25519);
        buf.put(privX25519);
        buf.put(pubX25519);
        buf.put(privMLDSA);
        buf.put(pubMLDSA);
        return buf.array();
    }

    /**
     * Deserialises from a blob produced by {@link #marshal()}.
     */
    public static DeviceIdentityKey unmarshal(byte[] raw) {
        if (raw == null || raw.length != MARSHAL_SIZE) {
            throw new IllegalArgumentException(
                    "DIK blob must be " + MARSHAL_SIZE + " bytes, got " + (raw == null ? 0 : raw.length));
        }
        ByteBuffer buf = ByteBuffer.wrap(raw);
        byte[] privEd = new byte[ED25519_PRIV_SIZE];
        buf.get(privEd);
        byte[] pubEd = new byte[ED25519_PUB_SIZE];
        buf.get(pubEd);
        byte[] privX = new byte[X25519_PRIV_SIZE];
        buf.get(privX);
        byte[] pubX = new byte[X25519_PUB_SIZE];
        buf.get(pubX);
        byte[] privMldsa = new byte[MLDSA65_PRIV_SIZE];
        buf.get(privMldsa);
        byte[] pubMldsa = new byte[MLDSA65_PUB_SIZE];
        buf.get(pubMldsa);
        return new DeviceIdentityKey(privEd, pubEd, privX, pubX, privMldsa, pubMldsa);
    }
}
