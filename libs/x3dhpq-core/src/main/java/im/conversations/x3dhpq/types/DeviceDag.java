// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * x3dhpq-xep-draft.md §11.7: multi-writer device-audit DAG engine. Byte- and
 * behaviour-compatible with the Dino (Vala) implementation in device_dag.vala.
 *
 * <p>Entries are ingested (deduped by content hash), then folded on demand in a
 * deterministic, content-derived topological order (Kahn, tie-broken by
 * (lamport, signer_fp, entry_hash)) — identical discipline to {@link MembershipDag}.
 *
 * <p>Authorization is simpler than the group journal: there is no admin set. Every
 * entry MUST be signed by the SAME account AIK, TOFU-pinned from the first
 * canonical-order entry (genesis AddDevice, or a genesis Snapshot for v1-&gt;v2
 * migration / prune-proof catch-up). {@code RotateAIK} re-pins the fold to a new
 * AIK for every subsequent entry — the ratchet root moves forward.
 */
public final class DeviceDag {

    /** Resolve a signer's AIK from its raw-hex fingerprint; null if unknown/untrusted. */
    public interface AikResolver {
        AccountIdentityPub resolve(String signerFpHex);
    }

    public static final class DeviceState {
        public final Map<Long, DeviceCertificate> authorized = new LinkedHashMap<>();
        public final Set<Long> removed = new HashSet<>();
        public AccountIdentityPub currentAik = null;
        public String currentAikFpHex = null;
        public long epoch = 0;
    }

    // entry_hash_hex -> entry
    private final Map<String, DeviceAuditEntryV2> store = new LinkedHashMap<>();

    public int size() { return store.size(); }

    /** Marshalled bytes of every stored entry — used for catch-up bundling. */
    public List<byte[]> getMarshalledEntries() {
        final List<byte[]> out = new ArrayList<>(store.size());
        for (final DeviceAuditEntryV2 e : store.values()) out.add(e.marshal());
        return out;
    }

    /** Parse + store; returns true if newly stored (not a duplicate). */
    public boolean ingest(byte[] bytes) {
        final DeviceAuditEntryV2 e = DeviceAuditEntryV2.unmarshal(bytes);
        if (e == null) return false;
        final String h = DeviceAuditEntryV2.hex(e.computeHash());
        if (store.containsKey(h)) return false;
        store.put(h, e);
        return true;
    }

    private List<DeviceAuditEntryV2> canonicalOrder() {
        // includable fixpoint: an entry is includable iff all its ancestors are present.
        final Set<String> includable = new HashSet<>();
        boolean changed = true;
        while (changed) {
            changed = false;
            for (final Map.Entry<String, DeviceAuditEntryV2> en : store.entrySet()) {
                if (includable.contains(en.getKey())) continue;
                boolean all = true;
                for (final byte[] p : en.getValue().getParents()) {
                    final String ph = DeviceAuditEntryV2.hex(p);
                    if (!store.containsKey(ph) || !includable.contains(ph)) { all = false; break; }
                }
                if (all) { includable.add(en.getKey()); changed = true; }
            }
        }
        final Map<String, Integer> indeg = new HashMap<>();
        final Map<String, List<String>> children = new HashMap<>();
        for (final String h : includable) indeg.put(h, 0);
        for (final String h : includable) {
            final DeviceAuditEntryV2 e = store.get(h);
            int d = 0;
            for (final byte[] p : e.getParents()) {
                final String ph = DeviceAuditEntryV2.hex(p);
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
        final List<DeviceAuditEntryV2> order = new ArrayList<>();
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

    private static int cmpKey(DeviceAuditEntryV2 a, DeviceAuditEntryV2 b) {
        if (a.getLamport() != b.getLamport()) return Long.compareUnsigned(a.getLamport(), b.getLamport());
        final int s = DeviceAuditEntryV2.hex(a.getSignerFp()).compareTo(DeviceAuditEntryV2.hex(b.getSignerFp()));
        if (s != 0) return s;
        return DeviceAuditEntryV2.hex(a.computeHash()).compareTo(DeviceAuditEntryV2.hex(b.computeHash()));
    }

    public DeviceState recompute(final AikResolver resolver) {
        final DeviceState st = new DeviceState();
        final List<DeviceAuditEntryV2> order = canonicalOrder();
        final Map<Long, String> removalNode = new HashMap<>();
        String pinnedFpHex = null;

        for (int i = 0; i < order.size(); i++) {
            final DeviceAuditEntryV2 e = order.get(i);
            final String signerHex = DeviceAuditEntryV2.hex(e.getSignerFp());

            if (i == 0) {
                final AccountIdentityPub candidate = resolver.resolve(signerHex);
                if (candidate == null || !e.verify(candidate)) continue;
                pinnedFpHex = signerHex;
                st.currentAik = candidate;
                st.currentAikFpHex = signerHex;
                st.epoch = 0;
            } else {
                if (!signerHex.equals(pinnedFpHex)) continue; // must be signed by the currently pinned AIK
                if (st.currentAik == null || !e.verify(st.currentAik)) continue;
                st.epoch = i;
            }

            switch (e.getAction()) {
                case DeviceAuditEntryV2.ACTION_ADD_DEVICE: {
                    final DeviceAuditEntryV2.AddDevicePayload p = DeviceAuditEntryV2.parseAddDevicePayload(e.getPayload());
                    if (p == null) break;
                    if (!canReAdd(st, removalNode, p.deviceId, e)) break;
                    DeviceCertificate dc = null;
                    try {
                        dc = DeviceCertificate.unmarshal(p.certBytes);
                    } catch (final RuntimeException ex) {
                        break; // malformed cert: reject the AddDevice
                    }
                    st.authorized.put(p.deviceId, dc);
                    st.removed.remove(p.deviceId);
                    break;
                }
                case DeviceAuditEntryV2.ACTION_REMOVE_DEVICE: {
                    final Long deviceId = DeviceAuditEntryV2.parseRemoveDevicePayload(e.getPayload());
                    if (deviceId == null) break;
                    st.authorized.remove(deviceId);
                    st.removed.add(deviceId);
                    removalNode.put(deviceId, DeviceAuditEntryV2.hex(e.computeHash()));
                    break;
                }
                case DeviceAuditEntryV2.ACTION_ROTATE_AIK: {
                    final AccountIdentityPub newAik = DeviceAuditEntryV2.parseRotateAikPayload(e.getPayload());
                    if (newAik == null) break;
                    st.currentAik = newAik;
                    pinnedFpHex = DeviceAuditEntryV2.hex(DeviceAuditEntryV2.aikFp(newAik));
                    st.currentAikFpHex = pinnedFpHex;
                    break;
                }
                case DeviceAuditEntryV2.ACTION_SNAPSHOT: {
                    if (i == 0) applyGenesisSnapshot(st, e);
                    // A mid-DAG Snapshot is a passive checkpoint only.
                    break;
                }
                default:
                    break;
            }
        }
        return st;
    }

    /** Import a genesis Snapshot's asserted device set (v1-&gt;v2 bridge / prune-proof catch-up). */
    private void applyGenesisSnapshot(DeviceState st, DeviceAuditEntryV2 e) {
        final DeviceAuditEntryV2.Snapshot snap = DeviceAuditEntryV2.parseSnapshot(e.getPayload());
        if (snap == null) return;
        for (final DeviceAuditEntryV2.SnapshotDevice d : snap.devices) {
            DeviceCertificate dc = null;
            try {
                dc = DeviceCertificate.unmarshal(d.certBytes);
            } catch (final RuntimeException ex) {
                continue; // skip malformed device entries only
            }
            st.authorized.put(d.deviceId, dc);
        }
        st.epoch = snap.epoch;
    }

    private boolean canReAdd(DeviceState st, Map<Long, String> removalNode, long deviceId, DeviceAuditEntryV2 add) {
        if (!st.removed.contains(deviceId)) return true;
        final String rn = removalNode.get(deviceId);
        if (rn == null) return true;
        return isAncestor(rn, add);
    }

    private boolean isAncestor(String ancestorHex, DeviceAuditEntryV2 descendant) {
        final Set<String> seen = new HashSet<>();
        final Deque<String> stack = new ArrayDeque<>();
        for (final byte[] p : descendant.getParents()) stack.push(DeviceAuditEntryV2.hex(p));
        while (!stack.isEmpty()) {
            final String h = stack.pop();
            if (h.equals(ancestorHex)) return true;
            if (!seen.add(h)) continue;
            final DeviceAuditEntryV2 pe = store.get(h);
            if (pe != null) for (final byte[] pp : pe.getParents()) stack.push(DeviceAuditEntryV2.hex(pp));
        }
        return false;
    }

    /** Current DAG heads (entries with no present children) — the parents[] for the next authored entry. */
    public List<byte[]> currentHeads() {
        final Set<String> hasChild = new HashSet<>();
        for (final DeviceAuditEntryV2 e : store.values()) {
            for (final byte[] p : e.getParents()) hasChild.add(DeviceAuditEntryV2.hex(p));
        }
        final List<byte[]> heads = new ArrayList<>();
        for (final Map.Entry<String, DeviceAuditEntryV2> en : store.entrySet()) {
            if (!hasChild.contains(en.getKey())) heads.add(en.getValue().computeHash());
        }
        return heads;
    }

    public long nextLamport() {
        long m = 0;
        for (final DeviceAuditEntryV2 e : store.values()) if (Long.compareUnsigned(e.getLamport(), m) > 0) m = e.getLamport();
        return m + 1;
    }
}
