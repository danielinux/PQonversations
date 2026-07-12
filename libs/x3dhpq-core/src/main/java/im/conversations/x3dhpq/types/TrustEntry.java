// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Trust Manifest — Phase 1: a single delegation entry in the account trust DAG.
 * Byte-compatible with the Dino (Vala) {@code trust_manifest.vala} implementation.
 *
 * <p>Unlike {@link DeviceAuditEntryV2} (single-AIK authority), a TrustEntry is authored
 * by ANY currently-trusted device (delegation): the entry is signed by the AUTHOR
 * device's DIK, except the genesis entry which is self-authored and signed by the
 * account AIK. Authorization is a fold over the DAG (see {@link TrustManifest#fold}).
 *
 * <p>signed_part layout (all integers big-endian):
 * <pre>
 *   "X3DHPQ-TrustEntry-v1\0" (21)
 *   action             uint8            1 = ADD, 2 = REMOVE
 *   device_id          uint32           the SUBJECT device id
 *   dc_len             uint16           length of dc_bytes
 *   dc_bytes           dc_len bytes     DeviceCertificate.marshal() of the subject
 *   lamport            uint64
 *   parent_count       uint32
 *   parents[N]         32 bytes each    SHA-256(parent TrustEntry.marshal()), raw, no len prefix
 *   author_device_id   uint32           the EDITOR device id (== device_id for genesis)
 *   author_dc_hash     32 bytes         SHA-256(author's DeviceCertificate.marshal()), raw
 *   timestamp          uint64           unix seconds (int64 cast to uint64)
 * </pre>
 * marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl;
 * entry_hash = SHA-256(marshal).
 */
public final class TrustEntry {

    public static final int ACTION_ADD    = 1;
    public static final int ACTION_REMOVE = 2;

    static final byte[] PREFIX = {
        'X','3','D','H','P','Q','-','T','r','u','s','t','E','n','t','r','y','-','v','1', 0x00
    };

    private final int action;               // uint8
    private final long deviceId;            // uint32, subject
    private final DeviceCertificate dc;     // subject device certificate
    private final long lamport;             // uint64
    private final List<byte[]> parents;     // each 32 bytes
    private final long authorDeviceId;      // uint32, editor
    private final byte[] authorDcHash;      // 32 bytes
    private final long timestamp;           // int64 as uint64
    private final byte[] sigEd;
    private final byte[] sigMl;

    public TrustEntry(int action, long deviceId, DeviceCertificate dc, long lamport,
                      List<byte[]> parents, long authorDeviceId, byte[] authorDcHash,
                      long timestamp, byte[] sigEd, byte[] sigMl) {
        this.action = action;
        this.deviceId = deviceId;
        this.dc = dc;
        this.lamport = lamport;
        this.parents = parents == null ? new ArrayList<>() : parents;
        this.authorDeviceId = authorDeviceId;
        this.authorDcHash = authorDcHash;
        this.timestamp = timestamp;
        this.sigEd = sigEd == null ? new byte[0] : sigEd;
        this.sigMl = sigMl == null ? new byte[0] : sigMl;
    }

    public int getAction() { return action; }
    public long getDeviceId() { return deviceId; }
    public DeviceCertificate getDc() { return dc; }
    public long getLamport() { return lamport; }
    public List<byte[]> getParents() { return parents; }
    public long getAuthorDeviceId() { return authorDeviceId; }
    public byte[] getAuthorDcHash() { return authorDcHash; }
    public long getTimestamp() { return timestamp; }
    public byte[] getSigEd25519() { return sigEd; }
    public byte[] getSigMLDSA() { return sigMl; }

    public byte[] signedPart() {
        final byte[] dcBytes = dc.marshal();
        final int size = PREFIX.length + 1 + 4 + 2 + dcBytes.length
                + 8 + 4 + parents.size() * 32 + 4 + 32 + 8;
        final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(PREFIX);
        buf.put((byte) action);
        buf.putInt((int) (deviceId & 0xFFFFFFFFL));
        buf.putShort((short) (dcBytes.length & 0xFFFF));
        buf.put(dcBytes);
        buf.putLong(lamport);
        buf.putInt(parents.size());
        for (final byte[] p : parents) buf.put(p, 0, 32);
        buf.putInt((int) (authorDeviceId & 0xFFFFFFFFL));
        buf.put(authorDcHash, 0, 32);
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

    /** Both hybrid signatures MUST verify under the given DIK/AIK pubs over signed_part. */
    public boolean verifySig(byte[] edPub, byte[] mlPub) {
        if (sigEd == null || sigMl == null || sigEd.length == 0 || sigMl.length == 0) return false;
        final byte[] sp = signedPart();
        return X3dhpqCrypto.ed25519Verify(edPub, sp, sigEd)
                && X3dhpqCrypto.mldsa65Verify(mlPub, sp, sigMl);
    }

    /** Genesis: entry signature verifies under the account AIK. */
    public boolean verifyUnderAik(AccountIdentityPub aik) {
        return verifySig(aik.getPubEd25519(), aik.getPubMLDSA());
    }

    /** Non-genesis: entry signature verifies under the author device's DIK pubs. */
    public boolean verifyUnderDc(DeviceCertificate authorDc) {
        return verifySig(authorDc.getDikPubEd25519(), authorDc.getDikPubMLDSA());
    }

    /** Parse from wire; returns null on any malformed input. */
    public static TrustEntry unmarshal(byte[] b) {
        final int min = PREFIX.length + 1 + 4 + 2 + 8 + 4 + 4 + 32 + 8 + 2 + 2;
        if (b == null || b.length < min) return null;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return null;
        try {
            final ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
            buf.position(PREFIX.length);
            final int action = buf.get() & 0xFF;
            final long deviceId = buf.getInt() & 0xFFFFFFFFL;
            final int dcLen = buf.getShort() & 0xFFFF;
            if (buf.remaining() < dcLen) return null;
            final byte[] dcBytes = new byte[dcLen];
            buf.get(dcBytes);
            final DeviceCertificate dc;
            try {
                dc = DeviceCertificate.unmarshal(dcBytes);
            } catch (final RuntimeException ex) {
                return null;
            }
            if (buf.remaining() < 8 + 4) return null;
            final long lamport = buf.getLong();
            final long pcLong = buf.getInt() & 0xFFFFFFFFL;
            if (pcLong > 4096) return null;
            final int pc = (int) pcLong;
            if ((long) buf.position() + (long) pc * 32 + 4 + 32 + 8 + 2 + 2 > b.length) return null;
            final List<byte[]> parents = new ArrayList<>(pc);
            for (int i = 0; i < pc; i++) {
                final byte[] p = new byte[32];
                buf.get(p);
                parents.add(p);
            }
            final long authorDeviceId = buf.getInt() & 0xFFFFFFFFL;
            final byte[] authorDcHash = new byte[32];
            buf.get(authorDcHash);
            final long timestamp = buf.getLong();
            final int sl = buf.getShort() & 0xFFFF;
            if ((long) buf.position() + sl + 2 > b.length) return null;
            final byte[] sigEd = new byte[sl];
            buf.get(sigEd);
            final int ml = buf.getShort() & 0xFFFF;
            if ((long) buf.position() + ml > b.length) return null;
            final byte[] sigMl = new byte[ml];
            buf.get(sigMl);
            return new TrustEntry(action, deviceId, dc, lamport, parents, authorDeviceId,
                    authorDcHash, timestamp, sigEd, sigMl);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    public static String hex(byte[] b) {
        final StringBuilder sb = new StringBuilder(b.length * 2);
        for (final byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /**
     * Build a fully signed TrustEntry. For the genesis entry pass the account AIK's
     * private keys (edPriv/mlPriv); for a delegated entry pass the author device DIK's
     * private keys. Mirrors the DeviceAuditEntryV2.signNew discipline so live-emitted
     * entries are byte-identical to unit-tested vectors.
     */
    public static TrustEntry signNew(int action, long deviceId, DeviceCertificate dc, long lamport,
                                     List<byte[]> parents, long authorDeviceId, byte[] authorDcHash,
                                     long timestamp, byte[] edPriv, byte[] mlPriv) {
        final TrustEntry unsigned = new TrustEntry(action, deviceId, dc, lamport, parents,
                authorDeviceId, authorDcHash, timestamp, new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(edPriv, sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(mlPriv, sp);
        return new TrustEntry(action, deviceId, dc, lamport, parents, authorDeviceId,
                authorDcHash, timestamp, sigEd, sigMl);
    }
}
