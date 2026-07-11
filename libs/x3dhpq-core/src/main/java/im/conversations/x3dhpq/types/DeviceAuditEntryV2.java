// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * x3dhpq-xep-draft.md §11.7: multi-writer device-audit DAG entry (v2). Byte-compatible
 * with the Dino (Vala) implementation in device_dag.vala.
 *
 * <p>Unlike {@link JournalEntryV2} (the group membership journal, which has a set of
 * admins), authorization here is simpler: every entry MUST be signed by the SAME
 * account AIK (TOFU-pinned at genesis / first Snapshot). {@code signer_fp} is that
 * AIK's fingerprint; {@code author_device_id} is attribution-only metadata for the
 * §11.6 "was this you?" UX and is never an authorization input.
 *
 * <p>signed_part layout (all integers big-endian):
 * <pre>
 *   "X3DHPQ-DevAudit-v2\0" (19)
 *   lamport            uint64
 *   signer_fp          20 bytes        (raw BLAKE2b-160 of the account AIK)
 *   author_device_id   uint32          (attribution only, never an authz input)
 *   parent_count       uint32
 *   parents[N]         32 bytes each   (SHA-256(marshal(parent)))
 *   action             uint8
 *   payload_len        uint32
 *   payload            payload_len bytes
 *   timestamp          int64 (as uint64)
 * </pre>
 * marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl;
 * entry_hash = SHA-256(marshal).
 */
public final class DeviceAuditEntryV2 {

    public static final int ACTION_ADD_DEVICE    = 1;
    public static final int ACTION_REMOVE_DEVICE = 2;
    public static final int ACTION_ROTATE_AIK    = 3;
    public static final int ACTION_SNAPSHOT      = 10;

    static final byte[] V2_PREFIX = {
        'X','3','D','H','P','Q','-','D','e','v','A','u','d','i','t','-','v','2', 0x00
    };

    private final long lamport;
    private final byte[] signerFp;         // 20 bytes; account AIK fp
    private final long authorDeviceId;     // uint32, attribution only
    private final List<byte[]> parents;    // each 32 bytes
    private final int action;
    private final byte[] payload;
    private final long timestamp;
    private final byte[] sigEd;
    private final byte[] sigMl;

    public DeviceAuditEntryV2(long lamport, byte[] signerFp, long authorDeviceId, List<byte[]> parents,
                               int action, byte[] payload, long timestamp, byte[] sigEd, byte[] sigMl) {
        this.lamport = lamport;
        this.signerFp = signerFp;
        this.authorDeviceId = authorDeviceId;
        this.parents = parents == null ? new ArrayList<>() : parents;
        this.action = action;
        this.payload = payload;
        this.timestamp = timestamp;
        this.sigEd = sigEd;
        this.sigMl = sigMl;
    }

    public long getLamport() { return lamport; }
    public byte[] getSignerFp() { return signerFp; }
    public long getAuthorDeviceId() { return authorDeviceId; }
    public List<byte[]> getParents() { return parents; }
    public int getAction() { return action; }
    public byte[] getPayload() { return payload; }
    public long getTimestamp() { return timestamp; }
    public byte[] getSigEd25519() { return sigEd; }
    public byte[] getSigMLDSA() { return sigMl; }

    public byte[] signedPart() {
        final int size = V2_PREFIX.length + 8 + 20 + 4 + 4 + parents.size() * 32 + 1 + 4 + payload.length + 8;
        final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(V2_PREFIX);
        buf.putLong(lamport);
        buf.put(signerFp, 0, 20);
        buf.putInt((int) (authorDeviceId & 0xFFFFFFFFL));
        buf.putInt(parents.size());
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

    /** Both hybrid signatures MUST verify under the single current account AIK. */
    public boolean verify(AccountIdentityPub aik) {
        if (sigEd == null || sigMl == null || sigEd.length == 0 || sigMl.length == 0) return false;
        final byte[] sp = signedPart();
        return X3dhpqCrypto.ed25519Verify(aik.getPubEd25519(), sp, sigEd)
                && X3dhpqCrypto.mldsa65Verify(aik.getPubMLDSA(), sp, sigMl);
    }

    public static boolean isV2(byte[] b) {
        if (b == null || b.length < V2_PREFIX.length) return false;
        for (int i = 0; i < V2_PREFIX.length; i++) if (b[i] != V2_PREFIX[i]) return false;
        return true;
    }

    /** Parse from wire; returns null on any malformed input. */
    public static DeviceAuditEntryV2 unmarshal(byte[] b) {
        final int min = V2_PREFIX.length + 8 + 20 + 4 + 4 + 1 + 4 + 8 + 2 + 2;
        if (b == null || b.length < min) return null;
        for (int i = 0; i < V2_PREFIX.length; i++) if (b[i] != V2_PREFIX[i]) return null;
        try {
            final ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
            buf.position(V2_PREFIX.length);
            final long lamport = buf.getLong();
            final byte[] signerFp = new byte[20];
            buf.get(signerFp);
            final long authorDeviceId = buf.getInt() & 0xFFFFFFFFL;
            final long pcLong = buf.getInt() & 0xFFFFFFFFL;
            if (pcLong > 4096) return null;
            final int pc = (int) pcLong;
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
            return new DeviceAuditEntryV2(lamport, signerFp, authorDeviceId, parents, action, payload, timestamp, sigEd, sigMl);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    public static String hex(byte[] b) {
        final StringBuilder sb = new StringBuilder(b.length * 2);
        for (final byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** Raw 20-byte BLAKE2b-160 fingerprint of an AIK (== the on-wire signer_fp). */
    public static byte[] aikFp(AccountIdentityPub aik) {
        return X3dhpqCrypto.BLAKE2B_160.hash(aik.marshal());
    }

    /**
     * Build a fully signed v2 entry authored by {@code deviceId} under {@code signer}
     * (the account AIK). Mirrors the test harness' sign() helper so live-emitted
     * entries are byte-identical to the unit-tested vectors.
     */
    public static DeviceAuditEntryV2 signNew(
            AccountIdentityKey signer, long lamport, long authorDeviceId, List<byte[]> parents,
            int action, byte[] payload, long timestamp) {
        final byte[] fp = aikFp(signer.getPublic());
        final DeviceAuditEntryV2 unsigned =
                new DeviceAuditEntryV2(lamport, fp, authorDeviceId, parents, action, payload, timestamp,
                        new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(signer.getPrivEd25519(), sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(signer.getPrivMLDSA(), sp);
        return new DeviceAuditEntryV2(lamport, fp, authorDeviceId, parents, action, payload, timestamp, sigEd, sigMl);
    }

    // -------------------------------------------------------------------------
    // §11.4 device action payload codecs (unchanged from v1, reused verbatim).
    // -------------------------------------------------------------------------

    /** AddDevice(1) payload: uint32(device_id) | uint32(cert_len) | DeviceCertificate.marshal(). */
    public static byte[] buildAddDevicePayload(long deviceId, byte[] certBytes) {
        final ByteBuffer buf = ByteBuffer.allocate(4 + 4 + certBytes.length).order(ByteOrder.BIG_ENDIAN);
        buf.putInt((int) (deviceId & 0xFFFFFFFFL));
        buf.putInt(certBytes.length);
        buf.put(certBytes);
        return buf.array();
    }

    public static final class AddDevicePayload {
        public final long deviceId;
        public final byte[] certBytes;
        public AddDevicePayload(long deviceId, byte[] certBytes) { this.deviceId = deviceId; this.certBytes = certBytes; }
    }

    public static AddDevicePayload parseAddDevicePayload(byte[] payload) {
        if (payload == null || payload.length < 8) return null;
        final ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        final long deviceId = buf.getInt() & 0xFFFFFFFFL;
        final long certLen = buf.getInt() & 0xFFFFFFFFL;
        if (certLen < 0 || 8 + certLen > payload.length) return null;
        final byte[] cert = new byte[(int) certLen];
        buf.get(cert);
        return new AddDevicePayload(deviceId, cert);
    }

    /** RemoveDevice(2) payload: uint32(device_id). */
    public static byte[] buildRemoveDevicePayload(long deviceId) {
        final ByteBuffer buf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        buf.putInt((int) (deviceId & 0xFFFFFFFFL));
        return buf.array();
    }

    public static Long parseRemoveDevicePayload(byte[] payload) {
        if (payload == null || payload.length < 4) return null;
        final ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        return buf.getInt() & 0xFFFFFFFFL;
    }

    /** RotateAIK(3) payload: uint16(new_aik_len) | AccountIdentityPub.marshal(). */
    public static byte[] buildRotateAikPayload(byte[] newAikMarshalled) {
        final ByteBuffer buf = ByteBuffer.allocate(2 + newAikMarshalled.length).order(ByteOrder.BIG_ENDIAN);
        buf.putShort((short) newAikMarshalled.length);
        buf.put(newAikMarshalled);
        return buf.array();
    }

    public static AccountIdentityPub parseRotateAikPayload(byte[] payload) {
        if (payload == null || payload.length < 2) return null;
        final ByteBuffer buf = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        final int len = buf.getShort() & 0xFFFF;
        if (2 + len > payload.length) return null;
        final byte[] aikBytes = new byte[len];
        buf.get(aikBytes);
        try {
            return AccountIdentityPub.unmarshal(aikBytes);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    // ---- Snapshot (action=10) payload codec (§11.7) ----
    // Layout (big-endian):
    //   owner_aik_fp(20) | epoch(uint64) | count(uint32)
    //   | { device_id(uint32) | cert_len(uint32) | DC.marshal() }*

    public static final class SnapshotDevice {
        public final long deviceId;
        public final byte[] certBytes; // opaque DeviceCertificate.marshal() bytes
        public SnapshotDevice(long deviceId, byte[] certBytes) { this.deviceId = deviceId; this.certBytes = certBytes; }
    }

    public static final class Snapshot {
        public final byte[] ownerAikFp; // 20 bytes
        public final long epoch;
        public final List<SnapshotDevice> devices;
        public Snapshot(byte[] ownerAikFp, long epoch, List<SnapshotDevice> devices) {
            this.ownerAikFp = ownerAikFp;
            this.epoch = epoch;
            this.devices = devices;
        }
    }

    public static byte[] buildSnapshotPayload(byte[] ownerAikFp20, long epoch, List<SnapshotDevice> devices) {
        int size = 20 + 8 + 4;
        for (final SnapshotDevice d : devices) size += 4 + 4 + d.certBytes.length;
        final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(ownerAikFp20, 0, 20);
        buf.putLong(epoch);
        buf.putInt(devices.size());
        for (final SnapshotDevice d : devices) {
            buf.putInt((int) (d.deviceId & 0xFFFFFFFFL));
            buf.putInt(d.certBytes.length);
            buf.put(d.certBytes);
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
            final long countLong = buf.getInt() & 0xFFFFFFFFL;
            if (countLong > 1_000_000) return null;
            final int count = (int) countLong;
            final List<SnapshotDevice> devices = new ArrayList<>(count);
            for (int i = 0; i < count; i++) {
                if (buf.remaining() < 8) return null;
                final long deviceId = buf.getInt() & 0xFFFFFFFFL;
                final long certLen = buf.getInt() & 0xFFFFFFFFL;
                if (certLen > buf.remaining()) return null;
                final byte[] cert = new byte[(int) certLen];
                buf.get(cert);
                devices.add(new SnapshotDevice(deviceId, cert));
            }
            return new Snapshot(ownerFp, epoch, devices);
        } catch (final RuntimeException e) {
            return null;
        }
    }
}
