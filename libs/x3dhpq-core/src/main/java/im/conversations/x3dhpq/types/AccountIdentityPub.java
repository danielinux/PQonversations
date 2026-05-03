// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

// Wire: uint16(1) | uint8(1) | 32-byte Ed25519 pub | 1952-byte ML-DSA-65 pub = 1987 bytes total.
public final class AccountIdentityPub {

    static final int ED25519_PUB_SIZE = 32;
    static final int MLDSA65_PUB_SIZE = 1952;

    final byte[] pubEd25519;
    final byte[] pubMLDSA;

    public AccountIdentityPub(byte[] pubEd25519, byte[] pubMLDSA) {
        if (pubEd25519 == null || pubEd25519.length != ED25519_PUB_SIZE) {
            throw new IllegalArgumentException("pubEd25519 must be 32 bytes");
        }
        if (pubMLDSA == null || pubMLDSA.length != MLDSA65_PUB_SIZE) {
            throw new IllegalArgumentException("pubMLDSA must be 1952 bytes");
        }
        this.pubEd25519 = Arrays.copyOf(pubEd25519, pubEd25519.length);
        this.pubMLDSA = Arrays.copyOf(pubMLDSA, pubMLDSA.length);
    }

    public byte[] getPubEd25519() {
        return Arrays.copyOf(pubEd25519, pubEd25519.length);
    }

    public byte[] getPubMLDSA() {
        return Arrays.copyOf(pubMLDSA, pubMLDSA.length);
    }

    // Wire encoding: uint16(version=1) | uint8(hasMLDSA=1) | Ed25519 pub | ML-DSA pub.
    public byte[] marshal() {
        int size = 2 + 1 + pubEd25519.length + pubMLDSA.length;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) 1);
        buf.put((byte) 1);
        buf.put(pubEd25519);
        buf.put(pubMLDSA);
        return buf.array();
    }

    public static AccountIdentityPub unmarshal(byte[] raw) {
        if (raw == null || raw.length < 3) {
            throw new IllegalArgumentException("AIK pub too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        short ver = buf.getShort();
        if (ver != 1) {
            throw new IllegalArgumentException("Unsupported AIK version: " + ver);
        }
        byte hasMLDSA = buf.get();
        if (hasMLDSA != 1) {
            throw new IllegalArgumentException("AIK missing ML-DSA-65 public key");
        }
        if (raw.length < 3 + ED25519_PUB_SIZE + MLDSA65_PUB_SIZE) {
            throw new IllegalArgumentException("AIK pub truncated");
        }
        byte[] ed = new byte[ED25519_PUB_SIZE];
        buf.get(ed);
        byte[] mldsa = new byte[MLDSA65_PUB_SIZE];
        buf.get(mldsa);
        return new AccountIdentityPub(ed, mldsa);
    }

    // Returns 30-char uppercase hex fingerprint in 6 groups of 5, e.g. "7AD37 1A1A3 67A62 B6533 1BC5A 2204C".
    // Algorithm: BLAKE2b-160 of marshal(), take first 15 bytes, hex-encode uppercase, split every 5 chars.
    public String fingerprint(Blake2b160 hasher) {
        byte[] digest = hasher.hash(marshal());
        // hex-encode the full 20-byte digest, take first 30 chars (= 15 bytes)
        StringBuilder hex = new StringBuilder(40);
        for (byte b : digest) {
            hex.append(String.format("%02X", b & 0xff));
        }
        String h30 = hex.substring(0, 30);
        return h30.substring(0, 5) + " " +
               h30.substring(5, 10) + " " +
               h30.substring(10, 15) + " " +
               h30.substring(15, 20) + " " +
               h30.substring(20, 25) + " " +
               h30.substring(25, 30);
    }

    public boolean equals(AccountIdentityPub other) {
        if (other == null) return false;
        return Arrays.equals(pubEd25519, other.pubEd25519) && Arrays.equals(pubMLDSA, other.pubMLDSA);
    }
}
