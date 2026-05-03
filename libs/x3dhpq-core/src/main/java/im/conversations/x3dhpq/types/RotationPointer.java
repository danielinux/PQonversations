// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Signed pointer from an old AIK to a new AIK, enabling key rotation with continuity.
 *
 * Signed by the OLD AIK (both Ed25519 and ML-DSA-65).
 *
 * Wire layout (mirrors Go aik_rotation.go SignedPart + Marshal):
 *   "X3DHPQ-Rotation-v1\x00" (19) | uint16 version
 *   | uint16 oldAikLen | <oldAIK.marshal()>
 *   | uint16 newAikLen | <newAIK.marshal()>
 *   | int64 rotatedAt
 *   | uint16 reasonLen | <reason UTF-8, max 512 bytes>
 *   [then marshal() appends:]
 *   | uint16 sigEdLen | sigEd | uint16 sigMLDSALen | sigMLDSA
 *
 * Prefix is "X3DHPQ-Rotation-v1\x00" = 19 bytes.
 */
public final class RotationPointer {

    static final byte[] ROTATION_PREFIX = {
        'X','3','D','H','P','Q','-','R','o','t','a','t','i','o','n','-','v','1',0x00
    };

    static final int MAX_REASON_BYTES = 512;

    final int version;          // uint16
    final AccountIdentityPub oldAikPub;
    final AccountIdentityPub newAikPub;
    final long rotatedAt;       // int64
    final String reason;
    final byte[] sigEd25519;
    final byte[] sigMLDSA;

    public RotationPointer(
            int version,
            AccountIdentityPub oldAikPub,
            AccountIdentityPub newAikPub,
            long rotatedAt,
            String reason,
            byte[] sigEd25519,
            byte[] sigMLDSA) {
        if (oldAikPub == null) throw new IllegalArgumentException("oldAikPub must not be null");
        if (newAikPub == null) throw new IllegalArgumentException("newAikPub must not be null");
        byte[] rb = (reason != null ? reason : "").getBytes(StandardCharsets.UTF_8);
        if (rb.length > MAX_REASON_BYTES) throw new IllegalArgumentException("reason exceeds 512 bytes");
        this.version    = version;
        this.oldAikPub  = oldAikPub;
        this.newAikPub  = newAikPub;
        this.rotatedAt  = rotatedAt;
        this.reason     = reason != null ? reason : "";
        this.sigEd25519 = sigEd25519 != null ? Arrays.copyOf(sigEd25519, sigEd25519.length) : new byte[0];
        this.sigMLDSA   = sigMLDSA   != null ? Arrays.copyOf(sigMLDSA,   sigMLDSA.length)   : new byte[0];
    }

    public int getVersion()                   { return version; }
    public AccountIdentityPub getOldAikPub()  { return oldAikPub; }
    public AccountIdentityPub getNewAikPub()  { return newAikPub; }
    public long getRotatedAt()                { return rotatedAt; }
    public String getReason()                 { return reason; }
    public byte[] getSigEd25519()             { return Arrays.copyOf(sigEd25519, sigEd25519.length); }
    public byte[] getSigMLDSA()               { return Arrays.copyOf(sigMLDSA, sigMLDSA.length); }

    /** Signed portion of the wire encoding (excludes signatures). */
    public byte[] signedPart() {
        byte[] oldBytes    = oldAikPub.marshal();
        byte[] newBytes    = newAikPub.marshal();
        byte[] reasonBytes = reason.getBytes(StandardCharsets.UTF_8);
        int size = ROTATION_PREFIX.length + 2
                + 2 + oldBytes.length
                + 2 + newBytes.length
                + 8
                + 2 + reasonBytes.length;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(ROTATION_PREFIX);
        buf.putShort((short) (version & 0xffff));
        buf.putShort((short) (oldBytes.length & 0xffff));
        buf.put(oldBytes);
        buf.putShort((short) (newBytes.length & 0xffff));
        buf.put(newBytes);
        buf.putLong(rotatedAt);
        buf.putShort((short) (reasonBytes.length & 0xffff));
        buf.put(reasonBytes);
        return buf.array();
    }

    /** Full wire encoding including both signatures. */
    public byte[] marshal() {
        byte[] sp = signedPart();
        int size = sp.length + 2 + sigEd25519.length + 2 + sigMLDSA.length;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(sp);
        buf.putShort((short) (sigEd25519.length & 0xffff));
        buf.put(sigEd25519);
        buf.putShort((short) (sigMLDSA.length & 0xffff));
        buf.put(sigMLDSA);
        return buf.array();
    }

    public static RotationPointer unmarshal(byte[] raw) {
        if (raw == null) throw new IllegalArgumentException("null input");
        int prefixLen = ROTATION_PREFIX.length;
        if (raw.length < prefixLen + 2) throw new IllegalArgumentException("RotationPointer too short");

        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
        byte[] prefixCheck = new byte[prefixLen];
        buf.get(prefixCheck);
        if (!Arrays.equals(prefixCheck, ROTATION_PREFIX)) {
            throw new IllegalArgumentException("RotationPointer: wrong prefix");
        }

        int version = buf.getShort() & 0xffff;

        byte[] oldBytes = readField(buf);
        AccountIdentityPub oldAik = AccountIdentityPub.unmarshal(oldBytes);

        byte[] newBytes = readField(buf);
        AccountIdentityPub newAik = AccountIdentityPub.unmarshal(newBytes);

        if (buf.remaining() < 8) throw new IllegalArgumentException("RotationPointer: truncated at rotatedAt");
        long rotatedAt = buf.getLong();

        byte[] reasonBytes = readField(buf);
        String reason = new String(reasonBytes, StandardCharsets.UTF_8);

        byte[] sigEd   = readField(buf);
        byte[] sigMLDSA = readField(buf);

        return new RotationPointer(version, oldAik, newAik, rotatedAt, reason, sigEd, sigMLDSA);
    }

    private static byte[] readField(ByteBuffer buf) {
        if (buf.remaining() < 2) throw new IllegalArgumentException("RotationPointer: truncated at length");
        int len = buf.getShort() & 0xffff;
        if (buf.remaining() < len) throw new IllegalArgumentException("RotationPointer: truncated at field");
        if (len == 0) return new byte[0];
        byte[] v = new byte[len];
        buf.get(v);
        return v;
    }
}
