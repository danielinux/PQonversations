// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * WS2: multi-admin membership journal entry (v2). Byte-compatible with the Dino
 * (Vala) implementation in membership_dag.vala.
 *
 * <p>signed_part layout (all integers big-endian):
 * <pre>
 *   "X3DHPQ-Audit-v2\0" (16)
 *   lamport        uint64          (&gt; max(parent.lamport), enforced by the DAG)
 *   signer_fp      20 bytes        (raw BLAKE2b-160 of the signing AIK)
 *   parent_count   uint16
 *   parents[N]     32 bytes each   (SHA-256(marshal(parent)))
 *   action         uint8
 *   payload_len    uint32
 *   payload        payload_len bytes
 *   timestamp      int64 (as uint64)
 * </pre>
 * marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl;
 * entry_hash = SHA-256(marshal).
 */
public final class JournalEntryV2 {

    public static final int ACTION_ADD_MEMBER    = 5;
    public static final int ACTION_REMOVE_MEMBER = 6;
    public static final int ACTION_ADD_ADMIN     = 7;
    public static final int ACTION_REMOVE_ADMIN  = 8;
    public static final int ACTION_SNAPSHOT      = 10;

    static final byte[] V2_PREFIX = {
        'X','3','D','H','P','Q','-','A','u','d','i','t','-','v','2', 0x00
    };

    private final long lamport;
    private final byte[] signerFp;       // 20 bytes
    private final List<byte[]> parents;  // each 32 bytes
    private final int action;
    private final byte[] payload;
    private final long timestamp;
    private final byte[] sigEd;
    private final byte[] sigMl;

    public JournalEntryV2(long lamport, byte[] signerFp, List<byte[]> parents, int action,
                          byte[] payload, long timestamp, byte[] sigEd, byte[] sigMl) {
        this.lamport = lamport;
        this.signerFp = signerFp;
        this.parents = parents == null ? new ArrayList<>() : parents;
        this.action = action;
        this.payload = payload;
        this.timestamp = timestamp;
        this.sigEd = sigEd;
        this.sigMl = sigMl;
    }

    public long getLamport() { return lamport; }
    public byte[] getSignerFp() { return signerFp; }
    public List<byte[]> getParents() { return parents; }
    public int getAction() { return action; }
    public byte[] getPayload() { return payload; }
    public long getTimestamp() { return timestamp; }
    public byte[] getSigEd25519() { return sigEd; }
    public byte[] getSigMLDSA() { return sigMl; }

    public byte[] signedPart() {
        final int size = 16 + 8 + 20 + 2 + parents.size() * 32 + 1 + 4 + payload.length + 8;
        final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(V2_PREFIX);
        buf.putLong(lamport);
        buf.put(signerFp, 0, 20);
        buf.putShort((short) parents.size());
        for (final byte[] p : parents) buf.put(p, 0, 32);
        buf.put((byte) action);
        buf.putInt(payload.length);
        buf.put(payload);
        buf.putLong(timestamp);
        return buf.array();
    }

    public byte[] marshal() {
        final byte[] sp = signedPart();
        final ByteBuffer buf =
                ByteBuffer.allocate(sp.length + 2 + sigEd.length + 2 + sigMl.length)
                        .order(ByteOrder.BIG_ENDIAN);
        buf.put(sp);
        buf.putShort((short) sigEd.length);
        buf.put(sigEd);
        buf.putShort((short) sigMl.length);
        buf.put(sigMl);
        return buf.array();
    }

    public byte[] computeHash() {
        return X3dhpqCrypto.sha256(marshal());
    }

    public boolean verify(AccountIdentityPub signer) {
        if (sigEd == null || sigMl == null || sigEd.length == 0 || sigMl.length == 0) return false;
        final byte[] sp = signedPart();
        return X3dhpqCrypto.ed25519Verify(signer.getPubEd25519(), sp, sigEd)
                && X3dhpqCrypto.mldsa65Verify(signer.getPubMLDSA(), sp, sigMl);
    }

    public static boolean isV2(byte[] b) {
        if (b == null || b.length < V2_PREFIX.length) return false;
        for (int i = 0; i < V2_PREFIX.length; i++) if (b[i] != V2_PREFIX[i]) return false;
        return true;
    }

    /** Parse from wire; returns null on any malformed input. */
    public static JournalEntryV2 unmarshal(byte[] b) {
        final int min = 16 + 8 + 20 + 2 + 1 + 4 + 8 + 2 + 2;
        if (b == null || b.length < min) return null;
        for (int i = 0; i < V2_PREFIX.length; i++) if (b[i] != V2_PREFIX[i]) return null;
        try {
            final ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
            buf.position(16);
            final long lamport = buf.getLong();
            final byte[] signerFp = new byte[20];
            buf.get(signerFp);
            final int pc = buf.getShort() & 0xFFFF;
            if (pc > 4096) return null;
            if ((long) buf.position() + (long) pc * 32 + 1 + 4 + 8 + 2 + 2 > b.length) return null;
            final List<byte[]> parents = new ArrayList<>(pc);
            for (int i = 0; i < pc; i++) {
                final byte[] p = new byte[32];
                buf.get(p);
                parents.add(p);
            }
            final int action = buf.get() & 0xFF;
            final long plLong = buf.getInt() & 0xFFFFFFFFL;
            if ((long) buf.position() + plLong + 8 + 2 + 2 > b.length) return null;
            final byte[] payload = new byte[(int) plLong];
            buf.get(payload);
            final long timestamp = buf.getLong();
            final int sl = buf.getShort() & 0xFFFF;
            if ((long) buf.position() + sl + 2 > b.length) return null;
            final byte[] sigEd = new byte[sl];
            buf.get(sigEd);
            final int ml = buf.getShort() & 0xFFFF;
            if ((long) buf.position() + ml > b.length) return null;
            final byte[] sigMl = new byte[ml];
            buf.get(sigMl);
            if (sl == 0 || ml == 0) return null;
            return new JournalEntryV2(lamport, signerFp, parents, action, payload, timestamp, sigEd, sigMl);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    /** 24-byte subject_fp(20)|epoch_after(4) payload, reused for AddAdmin/RemoveAdmin. */
    public static byte[] buildMemberPayload(byte[] fp20, long epochAfter) {
        return AuditEntry.buildMemberPayload(fp20, epochAfter);
    }

    /** 25-byte RemoveMember payload with an explicit ban flag (bit0). */
    public static byte[] buildRemovePayload(byte[] fp20, long epochAfter, boolean ban) {
        final byte[] base = AuditEntry.buildMemberPayload(fp20, epochAfter);
        final byte[] out = new byte[25];
        System.arraycopy(base, 0, out, 0, 24);
        out[24] = (byte) (ban ? 0x01 : 0x00);
        return out;
    }

    public static byte[] parseSubjectFp(byte[] payload) {
        if (payload == null || payload.length < 20) return null;
        final byte[] fp = new byte[20];
        System.arraycopy(payload, 0, fp, 0, 20);
        return fp;
    }

    public static boolean payloadIsBan(byte[] payload) {
        return payload != null && payload.length >= 25 && (payload[24] & 0x01) != 0;
    }

    public static String hex(byte[] b) {
        final StringBuilder sb = new StringBuilder(b.length * 2);
        for (final byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // WS2 live-path helpers: signing builder + Snapshot payload codec.
    // These add functionality only; they do NOT alter the wire layout of an
    // entry (signedPart/marshal/unmarshal above), so the shared cross-client
    // byte-vector remains locked.
    // -------------------------------------------------------------------------

    /** Raw 20-byte BLAKE2b-160 signer fingerprint of an AIK (== the on-wire signer_fp). */
    public static byte[] signerFp(AccountIdentityPub aik) {
        return X3dhpqCrypto.BLAKE2B_160.hash(aik.marshal());
    }

    /**
     * Build a fully signed v2 entry authored by {@code signer}. Mirrors the
     * test harness' sign() helper so live-emitted entries are byte-identical to
     * the unit-tested vectors.
     */
    public static JournalEntryV2 signNew(
            AccountIdentityKey signer, long lamport, List<byte[]> parents,
            int action, byte[] payload, long timestamp) {
        final byte[] fp = signerFp(signer.getPublic());
        final JournalEntryV2 unsigned =
                new JournalEntryV2(lamport, fp, parents, action, payload, timestamp,
                        new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(signer.getPrivEd25519(), sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(signer.getPrivMLDSA(), sp);
        return new JournalEntryV2(lamport, fp, parents, action, payload, timestamp, sigEd, sigMl);
    }

    // ---- Snapshot (action=10) payload codec (§13.1a) ----
    // Layout (big-endian):
    //   owner_fp(20) | epoch(uint64) | member_count(uint32)
    //   | { fp(20) | is_admin(uint8) }*
    //   | banned_count(uint32) | { fp(20) | removal_epoch(uint32) }*

    public static final class SnapshotMember {
        public final byte[] fp;      // 20 bytes
        public final boolean admin;
        public SnapshotMember(byte[] fp, boolean admin) { this.fp = fp; this.admin = admin; }
    }

    public static final class SnapshotBanned {
        public final byte[] fp;      // 20 bytes
        public final long removalEpoch;
        public SnapshotBanned(byte[] fp, long removalEpoch) { this.fp = fp; this.removalEpoch = removalEpoch; }
    }

    public static final class Snapshot {
        public final byte[] ownerFp; // 20 bytes
        public final long epoch;
        public final List<SnapshotMember> members;
        public final List<SnapshotBanned> banned;
        public Snapshot(byte[] ownerFp, long epoch, List<SnapshotMember> members, List<SnapshotBanned> banned) {
            this.ownerFp = ownerFp;
            this.epoch = epoch;
            this.members = members;
            this.banned = banned;
        }
    }

    public static byte[] buildSnapshotPayload(
            byte[] ownerFp20, long epoch,
            List<SnapshotMember> members, List<SnapshotBanned> banned) {
        final int size = 20 + 8 + 4 + members.size() * 21 + 4 + banned.size() * 24;
        final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(ownerFp20, 0, 20);
        buf.putLong(epoch);
        buf.putInt(members.size());
        for (final SnapshotMember m : members) {
            buf.put(m.fp, 0, 20);
            buf.put((byte) (m.admin ? 0x01 : 0x00));
        }
        buf.putInt(banned.size());
        for (final SnapshotBanned b : banned) {
            buf.put(b.fp, 0, 20);
            buf.putInt((int) (b.removalEpoch & 0xFFFFFFFFL));
        }
        return buf.array();
    }

    /** Parse a Snapshot payload; returns null on malformed input. */
    public static Snapshot parseSnapshot(byte[] payload) {
        if (payload == null || payload.length < 20 + 8 + 4) return null;
        try {
            final ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
            final byte[] ownerFp = new byte[20];
            buf.get(ownerFp);
            final long epoch = buf.getLong();
            final int mc = buf.getInt();
            if (mc < 0 || (long) buf.position() + (long) mc * 21 + 4 > payload.length) return null;
            final List<SnapshotMember> members = new ArrayList<>(mc);
            for (int i = 0; i < mc; i++) {
                final byte[] fp = new byte[20];
                buf.get(fp);
                final boolean admin = (buf.get() & 0x01) != 0;
                members.add(new SnapshotMember(fp, admin));
            }
            final int bc = buf.getInt();
            if (bc < 0 || (long) buf.position() + (long) bc * 24 > payload.length) return null;
            final List<SnapshotBanned> banned = new ArrayList<>(bc);
            for (int i = 0; i < bc; i++) {
                final byte[] fp = new byte[20];
                buf.get(fp);
                final long re = buf.getInt() & 0xFFFFFFFFL;
                banned.add(new SnapshotBanned(fp, re));
            }
            return new Snapshot(ownerFp, epoch, members, banned);
        } catch (final RuntimeException e) {
            return null;
        }
    }
}
