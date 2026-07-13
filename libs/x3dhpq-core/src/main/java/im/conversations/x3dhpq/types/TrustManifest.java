// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Trust Manifest v2 — the published head of the account trust SNAPSHOT. Byte-compatible
 * with the Dino (Vala) {@code trust_manifest.vala} v2 implementation.
 *
 * <p>v2 is a COMPACT SNAPSHOT of the current members (no history / no DAG): each publish
 * is a fresh snapshot chained to the previous version only by {@code prev_hash}. All
 * manifest hashing uses SHA-512. A manifest embeds the account root (AIK) and the full
 * list of {@link TrustEntry} membership entries. Folding (see {@link #fold}) yields the
 * authorized device set: genesis is verified under the AIK; every later ADD is authored by
 * the genesis device's DIK, ordered by ascending device id (no topo sort).
 *
 * <p>signed_part layout (all integers big-endian):
 * <pre>
 *   "X3DHPQ-TrustManifest-v2\0" (24)
 *   version            uint64           strictly increasing across publishes
 *   prev_hash_len      uint32           ALWAYS 64
 *   prev_hash          64 bytes         SHA-512(previous TrustManifest.marshal()); 64 zeros at genesis
 *   aik_len            uint16           length of aik_bytes (1987)
 *   aik_bytes          aik_len bytes    AccountIdentityPub.marshal()
 *   entry_count        uint32
 *   entries[N]         uint32 entry_len | TrustEntry.marshal()
 * </pre>
 * marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl;
 * manifest_hash = SHA-512(marshal) — becomes the prev_hash of the next version.
 */
public final class TrustManifest {

    static final byte[] PREFIX = {
        'X','3','D','H','P','Q','-','T','r','u','s','t','M','a','n','i','f','e','s','t','-','v','2', 0x00
    };

    private final long version;             // uint64
    private final byte[] prevHash;          // 64 bytes
    private final AccountIdentityPub aik;
    private final List<TrustEntry> entries;
    private final byte[] sigEd;
    private final byte[] sigMl;

    public TrustManifest(long version, byte[] prevHash, AccountIdentityPub aik,
                         List<TrustEntry> entries, byte[] sigEd, byte[] sigMl) {
        this.version = version;
        this.prevHash = prevHash;
        this.aik = aik;
        this.entries = entries == null ? new ArrayList<>() : entries;
        this.sigEd = sigEd == null ? new byte[0] : sigEd;
        this.sigMl = sigMl == null ? new byte[0] : sigMl;
    }

    public long getVersion() { return version; }
    public byte[] getPrevHash() { return prevHash; }
    public AccountIdentityPub getAik() { return aik; }
    public List<TrustEntry> getEntries() { return entries; }
    public byte[] getSigEd25519() { return sigEd; }
    public byte[] getSigMLDSA() { return sigMl; }

    public byte[] signedPart() {
        final byte[] aikBytes = aik.marshal();
        final List<byte[]> entryBytes = new ArrayList<>(entries.size());
        int entriesSize = 0;
        for (final TrustEntry e : entries) {
            final byte[] m = e.marshal();
            entryBytes.add(m);
            entriesSize += 4 + m.length;
        }
        final int size = PREFIX.length + 8 + 4 + 64 + 2 + aikBytes.length + 4 + entriesSize;
        final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(PREFIX);
        buf.putLong(version);
        buf.putInt(64);
        buf.put(prevHash, 0, 64);
        buf.putShort((short) (aikBytes.length & 0xFFFF));
        buf.put(aikBytes);
        buf.putInt(entries.size());
        for (final byte[] m : entryBytes) {
            buf.putInt(m.length);
            buf.put(m);
        }
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
        return X3dhpqCrypto.sha512(marshal());
    }

    /** Both hybrid signatures verify under the publishing device's DIK over signed_part. */
    public boolean verifySig(byte[] edPub, byte[] mlPub) {
        if (sigEd == null || sigMl == null || sigEd.length == 0 || sigMl.length == 0) return false;
        final byte[] sp = signedPart();
        return X3dhpqCrypto.ed25519Verify(edPub, sp, sigEd)
                && X3dhpqCrypto.mldsa65Verify(mlPub, sp, sigMl);
    }

    // -------------------------------------------------------------------------
    // HEAD signature. The publishing device signs signed_part() with its DIK (the
    // genesis-only device signs its own head at genesis). Interop-safe: the signed
    // input is the KAT-locked signed_part and Ed25519/ML-DSA-65 are standard.
    // -------------------------------------------------------------------------

    /**
     * Return a copy of this manifest whose head is signed under the publishing device's
     * DIK private keys (edPriv/mldsaPriv) over {@link #signedPart()}.
     */
    public TrustManifest signHead(byte[] dikPrivEd, byte[] dikPrivMldsa) {
        final byte[] sp = signedPart();
        final byte[] ed = X3dhpqCrypto.ed25519Sign(dikPrivEd, sp);
        final byte[] ml = X3dhpqCrypto.mldsa65Sign(dikPrivMldsa, sp);
        return new TrustManifest(version, prevHash, aik, entries, ed, ml);
    }

    /** True iff BOTH hybrid head signatures verify under the given DIK public keys. */
    public boolean verifyHead(byte[] dikPubEd, byte[] dikPubMldsa) {
        return verifySig(dikPubEd, dikPubMldsa);
    }

    /** Parse from wire; returns null on any malformed input. */
    public static TrustManifest unmarshal(byte[] b) {
        final int min = PREFIX.length + 8 + 4 + 64 + 2 + 4 + 2 + 2;
        if (b == null || b.length < min) return null;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return null;
        try {
            final ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
            buf.position(PREFIX.length);
            final long version = buf.getLong();
            final long prevLen = buf.getInt() & 0xFFFFFFFFL;
            if (prevLen != 64) return null;
            final byte[] prevHash = new byte[64];
            buf.get(prevHash);
            final int aikLen = buf.getShort() & 0xFFFF;
            if (buf.remaining() < aikLen) return null;
            final byte[] aikBytes = new byte[aikLen];
            buf.get(aikBytes);
            final AccountIdentityPub aik;
            try {
                aik = AccountIdentityPub.unmarshal(aikBytes);
            } catch (final RuntimeException ex) {
                return null;
            }
            if (buf.remaining() < 4) return null;
            final long ecLong = buf.getInt() & 0xFFFFFFFFL;
            if (ecLong > 1_000_000) return null;
            final int ec = (int) ecLong;
            final List<TrustEntry> entries = new ArrayList<>(ec);
            for (int i = 0; i < ec; i++) {
                if (buf.remaining() < 4) return null;
                final long enLong = buf.getInt() & 0xFFFFFFFFL;
                if (enLong > buf.remaining()) return null;
                final byte[] em = new byte[(int) enLong];
                buf.get(em);
                final TrustEntry e = TrustEntry.unmarshal(em);
                if (e == null) return null;
                entries.add(e);
            }
            if (buf.remaining() < 2) return null;
            final int sl = buf.getShort() & 0xFFFF;
            if (buf.remaining() < sl + 2) return null;
            final byte[] sigEd = new byte[sl];
            buf.get(sigEd);
            final int ml = buf.getShort() & 0xFFFF;
            if (buf.remaining() < ml) return null;
            final byte[] sigMl = new byte[ml];
            buf.get(sigMl);
            return new TrustManifest(version, prevHash, aik, entries, sigEd, sigMl);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Fold (trust derivation) — v2 SNAPSHOT model, identical algorithm to the Vala client.
    // -------------------------------------------------------------------------

    /**
     * Fold a snapshot manifest into the authorized device set: {@code device_id ->
     * DeviceCertificate} for every trusted member. v2 simplified fold:
     * <ol>
     *   <li>Identify the GENESIS entry: action==ADD, author_device_id == device_id, whose
     *       entry signature verifies under {@code m.aik}, whose embedded DC verifies under
     *       {@code m.aik}, and {@code dc.device_id == device_id}. If none valid ⇒ empty fold.</li>
     *   <li>Order the remaining entries by ascending unsigned device_id. Accept each iff its
     *       author is the genesis device, its {@code author_dc_hash == SHA-512(genesis DC)},
     *       its signature verifies under the genesis DC's DIK pubs, and {@code dc.device_id ==
     *       device_id}. A bad entry is dropped (never fatal). No REMOVE / removal-wins — a
     *       revoked device is simply absent from the snapshot.</li>
     * </ol>
     */
    public static Map<Long, DeviceCertificate> fold(TrustManifest manifest) {
        final AccountIdentityPub aik = manifest.aik;

        // 1. Genesis: the first entry that is self-authored, AIK-signed, with an AIK-verified DC.
        TrustEntry genesis = null;
        for (final TrustEntry e : manifest.entries) {
            if (e.getAction() != TrustEntry.ACTION_ADD) continue;
            if (e.getAuthorDeviceId() != e.getDeviceId()) continue;
            final DeviceCertificate dc = e.getDc();
            if (dc == null || dc.getDeviceId() != e.getDeviceId()) continue;
            if (!e.verifyUnderAik(aik)) continue;
            if (!verifyDcUnderAik(dc, aik)) continue;
            genesis = e;
            break;
        }
        if (genesis == null) return new LinkedHashMap<>();

        final long genesisId = genesis.getDeviceId();
        final DeviceCertificate genesisDc = genesis.getDc();
        final byte[] genesisDcHash = X3dhpqCrypto.sha512(genesisDc.marshal());

        final Map<Long, DeviceCertificate> trusted = new LinkedHashMap<>();
        trusted.put(genesisId, genesisDc);

        // 2. Remaining entries, ordered by ascending unsigned device_id.
        final List<TrustEntry> rest = new ArrayList<>();
        for (final TrustEntry e : manifest.entries) {
            if (e != genesis) rest.add(e);
        }
        rest.sort((a, b) -> Long.compareUnsigned(a.getDeviceId(), b.getDeviceId()));

        for (final TrustEntry e : rest) {
            if (e.getAction() != TrustEntry.ACTION_ADD) continue;
            if (e.getAuthorDeviceId() != genesisId) continue;
            final DeviceCertificate dc = e.getDc();
            if (dc == null || dc.getDeviceId() != e.getDeviceId()) continue;
            if (!Arrays.equals(e.getAuthorDcHash(), genesisDcHash)) continue;
            if (!e.verifyUnderDc(genesisDc)) continue;
            trusted.put(e.getDeviceId(), dc);
        }
        return trusted;
    }

    static boolean verifyDcUnderAik(DeviceCertificate dc, AccountIdentityPub aik) {
        final byte[] sigEd = dc.getSigEd25519();
        final byte[] sigMl = dc.getSigMLDSA();
        if (sigEd == null || sigMl == null || sigEd.length == 0 || sigMl.length == 0) return false;
        final byte[] sp = dc.signedPart();
        return X3dhpqCrypto.ed25519Verify(aik.getPubEd25519(), sp, sigEd)
                && X3dhpqCrypto.mldsa65Verify(aik.getPubMLDSA(), sp, sigMl);
    }
}
