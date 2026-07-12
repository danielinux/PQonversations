// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Trust Manifest — Phase 1: the published head of the account trust DAG. Byte-compatible
 * with the Dino (Vala) {@code trust_manifest.vala} implementation.
 *
 * <p>A manifest embeds the account root (AIK) and the full list of {@link TrustEntry}
 * delegation entries. Folding the DAG (see {@link #fold}) yields the authorized device
 * set to encrypt to: genesis is verified under the AIK; every later entry is authorized
 * by a currently-trusted author device's DIK (delegation), removal-wins per device.
 *
 * <p>signed_part layout (all integers big-endian):
 * <pre>
 *   "X3DHPQ-TrustManifest-v1\0" (24)
 *   version            uint64           strictly increasing across publishes
 *   prev_hash_len      uint32           ALWAYS 32
 *   prev_hash          32 bytes         SHA-256(previous TrustManifest.marshal()); 32 zeros at genesis
 *   aik_len            uint16           length of aik_bytes (1987)
 *   aik_bytes          aik_len bytes    AccountIdentityPub.marshal()
 *   entry_count        uint32
 *   entries[N]         uint32 entry_len | TrustEntry.marshal()
 * </pre>
 * marshal = signed_part | uint16 sigEdLen | sigEd | uint16 sigMlLen | sigMl;
 * manifest_hash = SHA-256(marshal) — becomes the prev_hash of the next version.
 */
public final class TrustManifest {

    static final byte[] PREFIX = {
        'X','3','D','H','P','Q','-','T','r','u','s','t','M','a','n','i','f','e','s','t','-','v','1', 0x00
    };

    private final long version;             // uint64
    private final byte[] prevHash;          // 32 bytes
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
        final int size = PREFIX.length + 8 + 4 + 32 + 2 + aikBytes.length + 4 + entriesSize;
        final ByteBuffer buf = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        buf.put(PREFIX);
        buf.putLong(version);
        buf.putInt(32);
        buf.put(prevHash, 0, 32);
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
        return X3dhpqCrypto.sha256(marshal());
    }

    /** Both hybrid signatures verify under the publishing device's DIK over signed_part. */
    public boolean verifySig(byte[] edPub, byte[] mlPub) {
        if (sigEd == null || sigMl == null || sigEd.length == 0 || sigMl.length == 0) return false;
        final byte[] sp = signedPart();
        return X3dhpqCrypto.ed25519Verify(edPub, sp, sigEd)
                && X3dhpqCrypto.mldsa65Verify(mlPub, sp, sigMl);
    }

    // -------------------------------------------------------------------------
    // Phase 2 — HEAD signature. The publishing device signs signed_part() with its
    // DIK (the genesis-only device signs its own head at genesis). Interop-safe:
    // the signed input is the Phase-1 KAT-locked signed_part and Ed25519/ML-DSA-65
    // are standard. See §B of the Trust Manifest Phase 2 contract.
    // -------------------------------------------------------------------------

    /**
     * Return a copy of this manifest whose head is signed under the publishing device's
     * DIK private keys ( edPriv/mldsaPriv) over {@link #signedPart()}. The manifest's
     * head fields (version/prev_hash/aik/entries) are unchanged.
     */
    public TrustManifest signHead(byte[] dikPrivEd, byte[] dikPrivMldsa) {
        final byte[] sp = signedPart();
        final byte[] ed = X3dhpqCrypto.ed25519Sign(dikPrivEd, sp);
        final byte[] ml = X3dhpqCrypto.mldsa65Sign(dikPrivMldsa, sp);
        return new TrustManifest(version, prevHash, aik, entries, ed, ml);
    }

    /**
     * True iff BOTH hybrid head signatures verify under the given DIK public keys over
     * {@link #signedPart()}. The caller resolves {@code dikPub*} from a currently-folded
     * device (§C step 5).
     */
    public boolean verifyHead(byte[] dikPubEd, byte[] dikPubMldsa) {
        return verifySig(dikPubEd, dikPubMldsa);
    }

    /** Parse from wire; returns null on any malformed input. */
    public static TrustManifest unmarshal(byte[] b) {
        final int min = PREFIX.length + 8 + 4 + 32 + 2 + 4 + 2 + 2;
        if (b == null || b.length < min) return null;
        for (int i = 0; i < PREFIX.length; i++) if (b[i] != PREFIX[i]) return null;
        try {
            final ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN);
            buf.position(PREFIX.length);
            final long version = buf.getLong();
            final long prevLen = buf.getInt() & 0xFFFFFFFFL;
            if (prevLen != 32) return null;
            final byte[] prevHash = new byte[32];
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
    // Fold / walk (trust derivation) — identical algorithm to the Vala client.
    // -------------------------------------------------------------------------

    /**
     * Fold a manifest into the authorized device set: {@code device_id -> DeviceCertificate}
     * for every device that is trusted and not removed. Mirrors {@link DeviceDag} discipline
     * (Kahn topo order, removal-wins ancestor check) but authorizes via delegation: any
     * currently-trusted author may add/remove, rooted at an AIK-signed genesis.
     */
    public static Map<Long, DeviceCertificate> fold(TrustManifest manifest) {
        final AccountIdentityPub aik = manifest.aik;

        // 1. store: entry_hash_hex -> entry
        final Map<String, TrustEntry> store = new LinkedHashMap<>();
        for (final TrustEntry e : manifest.entries) {
            store.put(TrustEntry.hex(e.computeHash()), e);
        }

        // 2. canonical topological order
        final List<TrustEntry> order = canonicalOrder(store);

        final Map<Long, DeviceCertificate> trusted = new LinkedHashMap<>();
        final Set<Long> removed = new HashSet<>();
        final Map<Long, String> removalNode = new HashMap<>();

        for (int i = 0; i < order.size(); i++) {
            final TrustEntry e = order.get(i);
            final DeviceCertificate dc = e.getDc();

            if (i == 0) {
                // Genesis: ADD, no parents, self-authored, AIK-signed, embedded DC AIK-verified,
                // and subject binding. Any failure => no trust at all.
                if (e.getAction() != TrustEntry.ACTION_ADD) return new LinkedHashMap<>();
                if (!e.getParents().isEmpty()) return new LinkedHashMap<>();
                if (e.getAuthorDeviceId() != e.getDeviceId()) return new LinkedHashMap<>();
                if (dc == null || dc.getDeviceId() != e.getDeviceId()) return new LinkedHashMap<>();
                if (!e.verifyUnderAik(aik)) return new LinkedHashMap<>();
                if (!verifyDcUnderAik(dc, aik)) return new LinkedHashMap<>();
                trusted.put(e.getDeviceId(), dc);
                continue;
            }

            // Later entries: authorize under a currently-trusted author (delegation).
            final long author = e.getAuthorDeviceId();
            if (!trusted.containsKey(author) || removed.contains(author)) continue;
            final DeviceCertificate authorDc = trusted.get(author);
            final byte[] expectHash = X3dhpqCrypto.sha256(authorDc.marshal());
            if (!Arrays.equals(expectHash, e.getAuthorDcHash())) continue;
            if (!e.verifyUnderDc(authorDc)) continue;
            if (dc == null || dc.getDeviceId() != e.getDeviceId()) continue;

            switch (e.getAction()) {
                case TrustEntry.ACTION_ADD: {
                    if (!canReAdd(store, removed, removalNode, e.getDeviceId(), e)) break;
                    trusted.put(e.getDeviceId(), dc);
                    removed.remove(e.getDeviceId());
                    break;
                }
                case TrustEntry.ACTION_REMOVE: {
                    trusted.remove(e.getDeviceId());
                    removed.add(e.getDeviceId());
                    removalNode.put(e.getDeviceId(), TrustEntry.hex(e.computeHash()));
                    break;
                }
                default:
                    break;
            }
        }

        final Map<Long, DeviceCertificate> result = new LinkedHashMap<>();
        for (final Map.Entry<Long, DeviceCertificate> en : trusted.entrySet()) {
            if (!removed.contains(en.getKey())) result.put(en.getKey(), en.getValue());
        }
        return result;
    }

    static boolean verifyDcUnderAik(DeviceCertificate dc, AccountIdentityPub aik) {
        final byte[] sigEd = dc.getSigEd25519();
        final byte[] sigMl = dc.getSigMLDSA();
        if (sigEd == null || sigMl == null || sigEd.length == 0 || sigMl.length == 0) return false;
        final byte[] sp = dc.signedPart();
        return X3dhpqCrypto.ed25519Verify(aik.getPubEd25519(), sp, sigEd)
                && X3dhpqCrypto.mldsa65Verify(aik.getPubMLDSA(), sp, sigMl);
    }

    private static List<TrustEntry> canonicalOrder(final Map<String, TrustEntry> store) {
        // includable fixpoint: an entry is includable iff all its parents are present AND includable.
        final Set<String> includable = new HashSet<>();
        boolean changed = true;
        while (changed) {
            changed = false;
            for (final Map.Entry<String, TrustEntry> en : store.entrySet()) {
                if (includable.contains(en.getKey())) continue;
                boolean all = true;
                for (final byte[] p : en.getValue().getParents()) {
                    final String ph = TrustEntry.hex(p);
                    if (!store.containsKey(ph) || !includable.contains(ph)) { all = false; break; }
                }
                if (all) { includable.add(en.getKey()); changed = true; }
            }
        }
        final Map<String, Integer> indeg = new HashMap<>();
        final Map<String, List<String>> children = new HashMap<>();
        for (final String h : includable) indeg.put(h, 0);
        for (final String h : includable) {
            final TrustEntry e = store.get(h);
            int d = 0;
            for (final byte[] p : e.getParents()) {
                final String ph = TrustEntry.hex(p);
                if (includable.contains(ph)) {
                    d++;
                    children.computeIfAbsent(ph, k -> new ArrayList<>()).add(h);
                }
            }
            indeg.put(h, d);
        }
        final Comparator<String> byKey = (a, b) -> cmpKey(store.get(a), store.get(b));
        final List<String> ready = new ArrayList<>();
        for (final String h : includable) if (indeg.get(h) == 0) ready.add(h);
        final List<TrustEntry> order = new ArrayList<>();
        while (!ready.isEmpty()) {
            ready.sort(byKey);
            final String h = ready.remove(0);
            order.add(store.get(h));
            final List<String> cs = children.get(h);
            if (cs != null) {
                for (final String c : cs) {
                    indeg.put(c, indeg.get(c) - 1);
                    if (indeg.get(c) == 0) ready.add(c);
                }
            }
        }
        return order;
    }

    private static int cmpKey(TrustEntry a, TrustEntry b) {
        if (a.getLamport() != b.getLamport()) return Long.compareUnsigned(a.getLamport(), b.getLamport());
        final int s = Integer.compareUnsigned((int) a.getAuthorDeviceId(), (int) b.getAuthorDeviceId());
        if (s != 0) return s;
        return TrustEntry.hex(a.computeHash()).compareTo(TrustEntry.hex(b.computeHash()));
    }

    private static boolean canReAdd(Map<String, TrustEntry> store, Set<Long> removed,
                                    Map<Long, String> removalNode, long deviceId, TrustEntry add) {
        if (!removed.contains(deviceId)) return true;
        final String rn = removalNode.get(deviceId);
        if (rn == null) return true;
        return isAncestor(store, rn, add);
    }

    private static boolean isAncestor(Map<String, TrustEntry> store, String ancestorHex, TrustEntry descendant) {
        final Set<String> seen = new HashSet<>();
        final Deque<String> stack = new ArrayDeque<>();
        for (final byte[] p : descendant.getParents()) stack.push(TrustEntry.hex(p));
        while (!stack.isEmpty()) {
            final String h = stack.pop();
            if (h.equals(ancestorHex)) return true;
            if (!seen.add(h)) continue;
            final TrustEntry pe = store.get(h);
            if (pe != null) for (final byte[] pp : pe.getParents()) stack.push(TrustEntry.hex(pp));
        }
        return false;
    }

    /** Current DAG heads (entries with no present child) — the parents[] for the next authored entry. */
    public List<byte[]> currentHeads() {
        final Map<String, TrustEntry> store = new LinkedHashMap<>();
        for (final TrustEntry e : entries) store.put(TrustEntry.hex(e.computeHash()), e);
        final Set<String> hasChild = new HashSet<>();
        for (final TrustEntry e : store.values()) {
            for (final byte[] p : e.getParents()) hasChild.add(TrustEntry.hex(p));
        }
        final List<byte[]> heads = new ArrayList<>();
        for (final Map.Entry<String, TrustEntry> en : store.entrySet()) {
            if (!hasChild.contains(en.getKey())) heads.add(en.getValue().computeHash());
        }
        return heads;
    }

    public long nextLamport() {
        long m = 0;
        for (final TrustEntry e : entries) if (Long.compareUnsigned(e.getLamport(), m) > 0) m = e.getLamport();
        return m + 1;
    }
}
