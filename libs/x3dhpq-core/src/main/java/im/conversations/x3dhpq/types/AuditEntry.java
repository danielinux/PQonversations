// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Per-account audit chain entry. Append-only, hash-linked.
 *
 * signedPart() wire layout (mirrors Go audit_chain.go SignedPart):
 *   "X3DHPQ-Audit-v1\x00" (16) | uint64 seq (8) | prevHash (32)
 *   | uint8 action (1) | uint32 payloadLen (4) | payload | int64 timestamp (8)
 *
 * marshal() appends: uint16 sigEdLen | sigEd | uint16 sigMLDSALen | sigMLDSA
 *
 * See Appendix-A vector A.4.
 */
public final class AuditEntry {

    // Action constants — match Go AuditAction enum values.
    public static final int ACTION_ADD_DEVICE          = 1;
    public static final int ACTION_REMOVE_DEVICE       = 2;
    public static final int ACTION_ROTATE_AIK          = 3;
    public static final int ACTION_RECOVER_FROM_BACKUP = 4;
    // Group membership journal actions (§13.8).
    public static final int ACTION_ADD_MEMBER          = 5;
    public static final int ACTION_REMOVE_MEMBER       = 6;

    /**
     * Builds the payload for AddMember / RemoveMember journal entries.
     * Wire: &lt;aik_fp 20 bytes&gt; | &lt;epoch_after uint32 BE&gt;.
     */
    public static byte[] buildMemberPayload(byte[] aikFp20, long epochAfter) {
        if (aikFp20 == null || aikFp20.length != 20) {
            throw new IllegalArgumentException("aikFp must be 20 bytes");
        }
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(24)
                .order(java.nio.ByteOrder.BIG_ENDIAN);
        buf.put(aikFp20);
        buf.putInt((int) (epochAfter & 0xFFFFFFFFL));
        return buf.array();
    }

    /**
     * Parses a member payload built by {@link #buildMemberPayload}.
     * Returns [aikFp20 (20 bytes), epochAfter (4 bytes)].
     */
    public static byte[][] parseMemberPayload(byte[] payload) {
        if (payload == null || payload.length < 24) {
            throw new IllegalArgumentException("member payload must be 24 bytes");
        }
        byte[] fp = new byte[20];
        System.arraycopy(payload, 0, fp, 0, 20);
        byte[] epochBytes = new byte[4];
        System.arraycopy(payload, 20, epochBytes, 0, 4);
        return new byte[][] { fp, epochBytes };
    }

    // Signing prefix, exactly 16 bytes: "X3DHPQ-Audit-v1\x00"
    static final byte[] AUDIT_PREFIX = {
        'X','3','D','H','P','Q','-','A','u','d','i','t','-','v','1',0x00
    };

    final long seq;
    final byte[] prevHash; // exactly 32 bytes
    final int action;
    final byte[] payload;
    final long timestamp;
    final byte[] sigEd25519;
    final byte[] sigMLDSA;

    public AuditEntry(
            long seq,
            byte[] prevHash,
            int action,
            byte[] payload,
            long timestamp,
            byte[] sigEd25519,
            byte[] sigMLDSA) {
        if (prevHash == null || prevHash.length != 32) {
            throw new IllegalArgumentException("prevHash must be 32 bytes");
        }
        this.seq        = seq;
        this.prevHash   = Arrays.copyOf(prevHash, 32);
        this.action     = action;
        this.payload    = payload != null ? Arrays.copyOf(payload, payload.length) : new byte[0];
        this.timestamp  = timestamp;
        this.sigEd25519 = sigEd25519 != null ? Arrays.copyOf(sigEd25519, sigEd25519.length) : new byte[0];
        this.sigMLDSA   = sigMLDSA  != null ? Arrays.copyOf(sigMLDSA,  sigMLDSA.length)  : new byte[0];
    }

    public long getSeq()           { return seq; }
    public byte[] getPrevHash()    { return Arrays.copyOf(prevHash, 32); }
    public int getAction()         { return action; }
    public byte[] getPayload()     { return Arrays.copyOf(payload, payload.length); }
    public long getTimestamp()     { return timestamp; }
    public byte[] getSigEd25519()  { return Arrays.copyOf(sigEd25519, sigEd25519.length); }
    public byte[] getSigMLDSA()    { return Arrays.copyOf(sigMLDSA, sigMLDSA.length); }

    /** Returns the signed portion of the wire encoding (no signatures). */
    public byte[] signedPart() {
        int size = AUDIT_PREFIX.length + 8 + 32 + 1 + 4 + payload.length + 8;
        ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(AUDIT_PREFIX);
        buf.putLong(seq);
        buf.put(prevHash);
        buf.put((byte) (action & 0xff));
        buf.putInt(payload.length);
        buf.put(payload);
        buf.putLong(timestamp);
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

    /** SHA-256 of marshal() — used as the prevHash link for the next entry. */
    public byte[] computeHash(Sha256 hasher) {
        return hasher.hash(marshal());
    }

    /**
     * Helper for callers building a chain: computes SHA-256(prevMarshaled) to get
     * the prevHash field value for the next entry.
     */
    public static byte[] computeNextHash(byte[] prevMarshaled, Sha256 hasher) {
        return hasher.hash(prevMarshaled);
    }

    public static AuditEntry unmarshal(byte[] raw) {
        if (raw == null) throw new IllegalArgumentException("null input");
        // minimum: prefix(16)+seq(8)+prevHash(32)+action(1)+payloadLen(4)+ts(8)+sigEdLen(2)+sigMLDSALen(2)
        int minSize = AUDIT_PREFIX.length + 8 + 32 + 1 + 4 + 8 + 2 + 2;
        if (raw.length < minSize) throw new IllegalArgumentException("AuditEntry too short");

        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);

        // verify prefix
        byte[] prefixCheck = new byte[AUDIT_PREFIX.length];
        buf.get(prefixCheck);
        if (!Arrays.equals(prefixCheck, AUDIT_PREFIX)) {
            throw new IllegalArgumentException("AuditEntry: wrong prefix");
        }

        long seq     = buf.getLong();
        byte[] prevH = new byte[32];
        buf.get(prevH);
        int action   = buf.get() & 0xff;
        int payLen   = buf.getInt();

        if (buf.remaining() < payLen + 8 + 2 + 2) {
            throw new IllegalArgumentException("AuditEntry: truncated after payloadLen");
        }
        byte[] payload = new byte[payLen];
        if (payLen > 0) buf.get(payload);

        long ts = buf.getLong();

        byte[] sigEd   = readField(buf);
        byte[] sigMLDSA = readField(buf);

        return new AuditEntry(seq, prevH, action, payload, ts, sigEd, sigMLDSA);
    }

    private static byte[] readField(ByteBuffer buf) {
        if (buf.remaining() < 2) throw new IllegalArgumentException("AuditEntry: truncated at length");
        int len = buf.getShort() & 0xffff;
        if (buf.remaining() < len) throw new IllegalArgumentException("AuditEntry: truncated at field");
        if (len == 0) return new byte[0];
        byte[] v = new byte[len];
        buf.get(v);
        return v;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuditEntry)) return false;
        AuditEntry e = (AuditEntry) o;
        return seq == e.seq
                && timestamp == e.timestamp
                && action == e.action
                && Arrays.equals(prevHash, e.prevHash)
                && Arrays.equals(payload, e.payload)
                && Arrays.equals(sigEd25519, e.sigEd25519)
                && Arrays.equals(sigMLDSA, e.sigMLDSA);
    }

    @Override
    public int hashCode() {
        int h = Long.hashCode(seq);
        h = 31 * h + Arrays.hashCode(prevHash);
        h = 31 * h + action;
        h = 31 * h + Arrays.hashCode(payload);
        h = 31 * h + Long.hashCode(timestamp);
        return h;
    }
}
