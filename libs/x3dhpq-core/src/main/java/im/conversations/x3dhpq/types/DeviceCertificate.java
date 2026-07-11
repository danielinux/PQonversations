// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

// Wire format mirrors Go DeviceCertificate; all multi-byte integers are big-endian.
// signedPart() layout: uint16(ver)|uint32(deviceId)|uint16(ed_len)|<ed>|uint16(x_len)|<x>|uint16(mldsa_len)|<mldsa>|int64(createdAt)|uint8(flags)
// marshal() appends:   uint16(sigEd_len)|<sigEd>|uint16(sigMLDSA_len)|<sigMLDSA>
// Signatures are computed/verified over signedPart() directly (no prefix), matching
// the canonical Go reference at internal/x3dhpqcrypto/devicecert.go and dino-fork.
public final class DeviceCertificate {

    public static final int FLAG_PRIMARY = 1;
    /**
     * @deprecated The Go reference and dino-fork sign signedPart() with no prefix.
     *   Wave A originally added this constant by misreading the spec; it is kept
     *   only for binary compat in case downstream Java callers reference it.
     *   New code MUST sign and verify against signedPart() directly.
     */
    @Deprecated
    public static final byte[] SIGNING_PREFIX =
            new byte[] {'X','3','D','H','P','Q','-','D','C','-','v','1',0x00};

    final int version;
    final long deviceId;
    final byte[] dikPubEd25519;
    final byte[] dikPubX25519;
    final byte[] dikPubMLDSA;
    final long createdAt;
    final byte flags;
    final byte[] sigEd25519;
    final byte[] sigMLDSA;

    public DeviceCertificate(
            int version,
            long deviceId,
            byte[] dikPubEd25519,
            byte[] dikPubX25519,
            byte[] dikPubMLDSA,
            long createdAt,
            byte flags,
            byte[] sigEd25519,
            byte[] sigMLDSA) {
        this.version = version;
        this.deviceId = deviceId;
        this.dikPubEd25519 = dikPubEd25519 != null ? Arrays.copyOf(dikPubEd25519, dikPubEd25519.length) : new byte[0];
        this.dikPubX25519 = dikPubX25519 != null ? Arrays.copyOf(dikPubX25519, dikPubX25519.length) : new byte[0];
        this.dikPubMLDSA = dikPubMLDSA != null ? Arrays.copyOf(dikPubMLDSA, dikPubMLDSA.length) : new byte[0];
        this.createdAt = createdAt;
        this.flags = flags;
        this.sigEd25519 = sigEd25519 != null ? Arrays.copyOf(sigEd25519, sigEd25519.length) : new byte[0];
        this.sigMLDSA = sigMLDSA != null ? Arrays.copyOf(sigMLDSA, sigMLDSA.length) : new byte[0];
    }

    public int getVersion()          { return version; }
    public long getDeviceId()        { return deviceId; }
    public byte[] getDikPubEd25519() { return Arrays.copyOf(dikPubEd25519, dikPubEd25519.length); }
    public byte[] getDikPubX25519()  { return Arrays.copyOf(dikPubX25519, dikPubX25519.length); }
    public byte[] getDikPubMLDSA()   { return Arrays.copyOf(dikPubMLDSA, dikPubMLDSA.length); }
    public long getCreatedAt()       { return createdAt; }
    public byte getFlags()           { return flags; }
    public byte[] getSigEd25519()    { return Arrays.copyOf(sigEd25519, sigEd25519.length); }
    public byte[] getSigMLDSA()      { return Arrays.copyOf(sigMLDSA, sigMLDSA.length); }

    // Returns the portion that is signed (before signatures are appended).
    public byte[] signedPart() {
        int size = 2 + 4
                + 2 + dikPubEd25519.length
                + 2 + dikPubX25519.length
                + 2 + dikPubMLDSA.length
                + 8 + 1;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) (version & 0xffff));
        // deviceId stored as uint32; cast to int for putInt (big-endian bit pattern preserved)
        buf.putInt((int) (deviceId & 0xffffffffL));
        buf.putShort((short) (dikPubEd25519.length & 0xffff));
        buf.put(dikPubEd25519);
        buf.putShort((short) (dikPubX25519.length & 0xffff));
        buf.put(dikPubX25519);
        buf.putShort((short) (dikPubMLDSA.length & 0xffff));
        buf.put(dikPubMLDSA);
        buf.putLong(createdAt);
        buf.put(flags);
        return buf.array();
    }

    public byte[] marshal() {
        byte[] sp = signedPart();
        int size = sp.length
                + 2 + sigEd25519.length
                + 2 + sigMLDSA.length;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(sp);
        buf.putShort((short) (sigEd25519.length & 0xffff));
        buf.put(sigEd25519);
        buf.putShort((short) (sigMLDSA.length & 0xffff));
        buf.put(sigMLDSA);
        return buf.array();
    }

    // Display-only fingerprint for device-management UIs (NOT part of any wire format or
    // signed input). Mirrors AccountIdentityPub#fingerprint: BLAKE2b-160 of marshal(), take
    // the first 15 bytes, hex-encode uppercase, split every 5 chars into 6 groups, e.g.
    // "7AD37 1A1A3 67A62 B6533 1BC5A 2204C".
    public String fingerprint(Blake2b160 hasher) {
        byte[] digest = hasher.hash(marshal());
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

    public static DeviceCertificate unmarshal(byte[] raw) {
        if (raw == null || raw.length < 6) {
            throw new IllegalArgumentException("DC too short");
        }
        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        int version = buf.getShort() & 0xffff;
        long deviceId = buf.getInt() & 0xffffffffL;

        byte[] dikPubEd25519 = readField(buf);
        byte[] dikPubX25519  = readField(buf);
        byte[] dikPubMLDSA   = readField(buf);

        if (buf.remaining() < 9) throw new IllegalArgumentException("DC truncated at timestamps");
        long createdAt = buf.getLong();
        byte flags = buf.get();

        byte[] sigEd25519 = readField(buf);
        byte[] sigMLDSA   = readField(buf);

        return new DeviceCertificate(version, deviceId,
                dikPubEd25519, dikPubX25519, dikPubMLDSA,
                createdAt, flags, sigEd25519, sigMLDSA);
    }

    private static byte[] readField(ByteBuffer buf) {
        if (buf.remaining() < 2) throw new IllegalArgumentException("DC truncated at length");
        int len = buf.getShort() & 0xffff;
        if (buf.remaining() < len) throw new IllegalArgumentException("DC truncated at field");
        if (len == 0) return new byte[0];
        byte[] v = new byte[len];
        buf.get(v);
        return v;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DeviceCertificate)) return false;
        DeviceCertificate other = (DeviceCertificate) o;
        return version == other.version
                && deviceId == other.deviceId
                && createdAt == other.createdAt
                && flags == other.flags
                && Arrays.equals(dikPubEd25519, other.dikPubEd25519)
                && Arrays.equals(dikPubX25519, other.dikPubX25519)
                && Arrays.equals(dikPubMLDSA, other.dikPubMLDSA)
                && Arrays.equals(sigEd25519, other.sigEd25519)
                && Arrays.equals(sigMLDSA, other.sigMLDSA);
    }

    @Override
    public int hashCode() {
        int h = 31 * version + Long.hashCode(deviceId);
        h = 31 * h + Arrays.hashCode(dikPubEd25519);
        h = 31 * h + Arrays.hashCode(dikPubX25519);
        h = 31 * h + Arrays.hashCode(dikPubMLDSA);
        h = 31 * h + Long.hashCode(createdAt);
        h = 31 * h + flags;
        h = 31 * h + Arrays.hashCode(sigEd25519);
        h = 31 * h + Arrays.hashCode(sigMLDSA);
        return h;
    }
}
