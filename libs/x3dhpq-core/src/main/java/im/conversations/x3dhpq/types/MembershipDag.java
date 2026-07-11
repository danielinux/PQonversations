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
 * WS2: multi-admin membership DAG. Byte- and behaviour-compatible with the Dino
 * (Vala) implementation in membership_dag.vala.
 *
 * <p>Entries are ingested (deduped by content hash), then folded on demand in a
 * deterministic, content-derived topological order (Kahn, tie-broken by
 * (lamport, signer_fp, entry_hash)) — so a malicious relay cannot change the
 * derived member/admin set by reordering.
 */
public final class MembershipDag {

    /** Resolve a signer's AIK from its raw-hex fingerprint; null if unknown. */
    public interface AikResolver {
        AccountIdentityPub resolve(String signerFpHex);
    }

    public static final class State {
        public final Set<String> members = new HashSet<>();
        public final Set<String> admins = new HashSet<>();
        public final Map<String, Long> removed = new HashMap<>(); // fp_hex -> removal epoch
        public final Set<String> banned = new HashSet<>();
        public String ownerFp = null;
        public long epoch = 0;
    }

    // entry_hash_hex -> entry
    private final Map<String, JournalEntryV2> store = new LinkedHashMap<>();

    public int size() { return store.size(); }

    /** Parse + store; returns true if newly stored (not a duplicate). */
    public boolean ingest(byte[] bytes) {
        final JournalEntryV2 e = JournalEntryV2.unmarshal(bytes);
        if (e == null) return false;
        final String h = JournalEntryV2.hex(e.computeHash());
        if (store.containsKey(h)) return false;
        store.put(h, e);
        return true;
    }

    private List<JournalEntryV2> canonicalOrder() {
        // includable fixpoint: an entry is includable iff all its ancestors are present.
        final Set<String> includable = new HashSet<>();
        boolean changed = true;
        while (changed) {
            changed = false;
            for (final Map.Entry<String, JournalEntryV2> en : store.entrySet()) {
                if (includable.contains(en.getKey())) continue;
                boolean all = true;
                for (final byte[] p : en.getValue().getParents()) {
                    final String ph = JournalEntryV2.hex(p);
                    if (!store.containsKey(ph) || !includable.contains(ph)) { all = false; break; }
                }
                if (all) { includable.add(en.getKey()); changed = true; }
            }
        }
        final Map<String, Integer> indeg = new HashMap<>();
        final Map<String, List<String>> children = new HashMap<>();
        for (final String h : includable) indeg.put(h, 0);
        for (final String h : includable) {
            final JournalEntryV2 e = store.get(h);
            int d = 0;
            for (final byte[] p : e.getParents()) {
                final String ph = JournalEntryV2.hex(p);
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
        final List<JournalEntryV2> order = new ArrayList<>();
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

    private static int cmpKey(JournalEntryV2 a, JournalEntryV2 b) {
        if (a.getLamport() != b.getLamport()) return Long.compareUnsigned(a.getLamport(), b.getLamport());
        final int s = JournalEntryV2.hex(a.getSignerFp()).compareTo(JournalEntryV2.hex(b.getSignerFp()));
        if (s != 0) return s;
        return JournalEntryV2.hex(a.computeHash()).compareTo(JournalEntryV2.hex(b.computeHash()));
    }

    public State recompute(final AikResolver resolver) {
        final State st = new State();
        final List<JournalEntryV2> order = canonicalOrder();
        final Map<String, String> removalNode = new HashMap<>();
        for (int i = 0; i < order.size(); i++) {
            final JournalEntryV2 e = order.get(i);
            final String signerHex = JournalEntryV2.hex(e.getSignerFp());
            final AccountIdentityPub signer = resolver.resolve(signerHex);
            if (signer == null) continue;
            if (!e.verify(signer)) continue;

            if (i == 0) {
                st.ownerFp = signerHex;
                st.admins.add(signerHex);
                st.members.add(signerHex);
                st.epoch = 0;
                continue;
            }
            st.epoch = i;
            if (!st.admins.contains(signerHex)) continue; // signer must be owner-or-admin

            final byte[] subject = JournalEntryV2.parseSubjectFp(e.getPayload());
            final String subjHex = subject != null ? JournalEntryV2.hex(subject) : "";

            switch (e.getAction()) {
                case JournalEntryV2.ACTION_ADD_MEMBER:
                    if (subjHex.equals(st.ownerFp)) break;
                    if (canReadd(st, removalNode, subjHex, e)) {
                        st.members.add(subjHex);
                        st.removed.remove(subjHex);
                    }
                    break;
                case JournalEntryV2.ACTION_ADD_ADMIN:
                    if (canReadd(st, removalNode, subjHex, e)) {
                        st.members.add(subjHex);
                        st.admins.add(subjHex);
                        st.removed.remove(subjHex);
                    }
                    break;
                case JournalEntryV2.ACTION_REMOVE_MEMBER:
                    if (subjHex.equals(st.ownerFp)) break; // owner irremovable
                    st.members.remove(subjHex);
                    st.admins.remove(subjHex);
                    st.removed.put(subjHex, st.epoch);
                    removalNode.put(subjHex, JournalEntryV2.hex(e.computeHash()));
                    if (JournalEntryV2.payloadIsBan(e.getPayload())) st.banned.add(subjHex);
                    break;
                case JournalEntryV2.ACTION_REMOVE_ADMIN:
                    if (subjHex.equals(st.ownerFp)) break; // owner undemotable
                    st.admins.remove(subjHex); // stays a member
                    break;
                case JournalEntryV2.ACTION_SNAPSHOT:
                default:
                    break;
            }
        }
        return st;
    }

    private boolean canReadd(State st, Map<String, String> removalNode, String fpHex, JournalEntryV2 add) {
        if (st.banned.contains(fpHex)) return false;
        if (!st.removed.containsKey(fpHex)) return true;
        final String rn = removalNode.get(fpHex);
        if (rn == null) return true;
        return isAncestor(rn, add);
    }

    private boolean isAncestor(String ancestorHex, JournalEntryV2 descendant) {
        final Set<String> seen = new HashSet<>();
        final Deque<String> stack = new ArrayDeque<>();
        for (final byte[] p : descendant.getParents()) stack.push(JournalEntryV2.hex(p));
        while (!stack.isEmpty()) {
            final String h = stack.pop();
            if (h.equals(ancestorHex)) return true;
            if (!seen.add(h)) continue;
            final JournalEntryV2 pe = store.get(h);
            if (pe != null) for (final byte[] pp : pe.getParents()) stack.push(JournalEntryV2.hex(pp));
        }
        return false;
    }

    /** Current DAG heads (entries with no present children) — the parents[] for the next authored entry. */
    public List<byte[]> currentHeads() {
        final Set<String> hasChild = new HashSet<>();
        for (final JournalEntryV2 e : store.values()) {
            for (final byte[] p : e.getParents()) hasChild.add(JournalEntryV2.hex(p));
        }
        final List<byte[]> heads = new ArrayList<>();
        for (final Map.Entry<String, JournalEntryV2> en : store.entrySet()) {
            if (!hasChild.contains(en.getKey())) heads.add(en.getValue().computeHash());
        }
        return heads;
    }

    public long nextLamport() {
        long m = 0;
        for (final JournalEntryV2 e : store.values()) if (Long.compareUnsigned(e.getLamport(), m) > 0) m = e.getLamport();
        return m + 1;
    }
}
