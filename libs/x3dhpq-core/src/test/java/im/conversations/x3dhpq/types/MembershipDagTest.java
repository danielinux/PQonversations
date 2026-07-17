// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import static org.junit.jupiter.api.Assertions.*;

import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** WS2: multi-admin membership DAG — convergence + authorization (plain JVM). */
class MembershipDagTest {

    // A signing identity with its AIK and raw-hex fingerprint.
    private static final class Id {
        final byte[] edPriv, mlPriv;
        final AccountIdentityPub pub;
        final byte[] fp;      // raw 20 bytes
        final String fpHex;

        Id() {
            final KeyPair ed = X3dhpqCrypto.ed25519GenerateKeypair();
            final KeyPair ml = X3dhpqCrypto.mldsa65GenerateKeypair();
            this.edPriv = ed.priv;
            this.mlPriv = ml.priv;
            this.pub = new AccountIdentityPub(ed.pub, ml.pub);
            this.fp = X3dhpqCrypto.BLAKE2B_160.hash(pub.marshal());
            this.fpHex = JournalEntryV2.hex(fp);
        }
    }

    private final Map<String, Id> registry = new HashMap<>();

    private Id makeId() {
        final Id id = new Id();
        registry.put(id.fpHex, id);
        return id;
    }

    private MembershipDag.AikResolver resolver() {
        return fpHex -> {
            final Id id = registry.get(fpHex);
            return id == null ? null : id.pub;
        };
    }

    private JournalEntryV2 sign(Id signer, long lamport, List<byte[]> parents, int action, byte[] payload, long ts) {
        final JournalEntryV2 unsigned =
                new JournalEntryV2(lamport, signer.fp, parents, action, payload, ts, new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(signer.edPriv, sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(signer.mlPriv, sp);
        return new JournalEntryV2(lamport, signer.fp, parents, action, payload, ts, sigEd, sigMl);
    }

    private List<byte[]> heads(byte[] h) {
        final List<byte[]> l = new ArrayList<>();
        if (h != null) l.add(h);
        return l;
    }

    private byte[] mp(byte[] fp) {
        return JournalEntryV2.buildMemberPayload(fp, 0);
    }

    // Fixed, deterministic v2 signed_part vector — asserted identically in the
    // Vala engine's test so the two clients are byte-compatible on the wire.
    // lamport=1, signer_fp=20xAB, no parents, action=AddMember(5),
    // payload=buildMemberPayload(20xCD, 0), timestamp=0.
    static final String V2_SIGNEDPART_VECTOR =
            "5833444850512d41756469742d763200"     // "X3DHPQ-Audit-v2\0"
          + "0000000000000001"                     // lamport
          + "abababababababababababababababababababab" // signer_fp
          + "0000"                                  // parent_count
          + "05"                                    // action = AddMember
          + "00000018"                              // payload_len = 24
          + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00000000" // payload
          + "0000000000000000";                     // timestamp

    @Test
    void signedPartVector() {
        final byte[] fp = new byte[20]; java.util.Arrays.fill(fp, (byte) 0xAB);
        final byte[] subj = new byte[20]; java.util.Arrays.fill(subj, (byte) 0xCD);
        final JournalEntryV2 e =
                new JournalEntryV2(1L, fp, new ArrayList<>(), JournalEntryV2.ACTION_ADD_MEMBER,
                        JournalEntryV2.buildMemberPayload(subj, 0), 0L, new byte[0], new byte[0]);
        assertEquals(V2_SIGNEDPART_VECTOR, JournalEntryV2.hex(e.signedPart()));
    }

    @Test
    void marshalRoundtrip() {
        final Id owner = makeId();
        final JournalEntryV2 e = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final byte[] wire = e.marshal();
        assertTrue(JournalEntryV2.isV2(wire));
        final JournalEntryV2 e2 = JournalEntryV2.unmarshal(wire);
        assertNotNull(e2);
        assertTrue(e2.verify(owner.pub));
        assertEquals(owner.fpHex, JournalEntryV2.hex(e2.getSignerFp()));
    }

    @Test
    void genesisAndLinearAdd() {
        final Id owner = makeId(), m1 = makeId();
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 a1 = sign(owner, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_MEMBER, mp(m1.fp), 1001);
        final MembershipDag dag = new MembershipDag();
        dag.ingest(g.marshal()); dag.ingest(a1.marshal());
        final MembershipDag.State st = dag.recompute(resolver());
        assertEquals(owner.fpHex, st.ownerFp);
        assertTrue(st.members.contains(m1.fpHex));
        assertTrue(st.admins.contains(owner.fpHex));
        assertFalse(st.admins.contains(m1.fpHex));
    }

    @Test
    void adminCanAddAfterPromotion() {
        final Id owner = makeId(), a = makeId(), m = makeId();
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 prom = sign(owner, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a.fp), 1001);
        final JournalEntryV2 add = sign(a, 2, heads(prom.computeHash()), JournalEntryV2.ACTION_ADD_MEMBER, mp(m.fp), 1002);
        final MembershipDag dag = new MembershipDag();
        dag.ingest(g.marshal()); dag.ingest(prom.marshal()); dag.ingest(add.marshal());
        final MembershipDag.State st = dag.recompute(resolver());
        assertTrue(st.admins.contains(a.fpHex));
        assertTrue(st.members.contains(m.fpHex), "member added by promoted admin");
    }

    @Test
    void nonAdminRejected() {
        final Id owner = makeId(), notAdmin = makeId(), m = makeId();
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 add = sign(notAdmin, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_MEMBER, mp(m.fp), 1001);
        final MembershipDag dag = new MembershipDag();
        dag.ingest(g.marshal()); dag.ingest(add.marshal());
        final MembershipDag.RecomputeResult rr = dag.recomputeDetailed(resolver());
        final MembershipDag.State st = rr.state;
        assertFalse(st.members.contains(m.fpHex), "add by non-admin must be rejected");
        assertEquals(1, rr.unauthorizedEntries, "unauthorized add should be surfaced");
    }

    @Test
    void missingParentStaysPending() {
        final Id owner = makeId(), m = makeId();
        final byte[] missing = new byte[32];
        java.util.Arrays.fill(missing, (byte) 0xA5);
        final JournalEntryV2 add = sign(owner, 1, heads(missing), JournalEntryV2.ACTION_ADD_MEMBER, mp(m.fp), 1001);
        final MembershipDag dag = new MembershipDag();
        dag.ingest(add.marshal());
        final MembershipDag.RecomputeResult rr = dag.recomputeDetailed(resolver());
        assertTrue(rr.missingParents.contains(JournalEntryV2.hex(missing)));
        assertFalse(rr.state.members.contains(m.fpHex), "entry with missing parent must not fold");
    }

    @Test
    void unknownSignerStaysPending() {
        final Id owner = makeId(), unknown = makeId(), m = makeId();
        registry.remove(unknown.fpHex);
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 add = sign(unknown, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_MEMBER, mp(m.fp), 1001);
        final MembershipDag dag = new MembershipDag();
        dag.ingest(g.marshal());
        dag.ingest(add.marshal());
        final MembershipDag.RecomputeResult rr = dag.recomputeDetailed(resolver());
        assertTrue(rr.unknownSigners.contains(unknown.fpHex));
        assertFalse(rr.state.members.contains(m.fpHex), "unknown signer must not authorize state");
    }

    @Test
    void removeMemberBanPreventsReadd() {
        final Id owner = makeId(), a = makeId(), m = makeId();
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 prom = sign(owner, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a.fp), 1001);
        final JournalEntryV2 add = sign(a, 2, heads(prom.computeHash()), JournalEntryV2.ACTION_ADD_MEMBER, mp(m.fp), 1002);
        final JournalEntryV2 ban = sign(a, 3, heads(add.computeHash()), JournalEntryV2.ACTION_REMOVE_MEMBER,
                JournalEntryV2.buildRemovePayload(m.fp, 0, true), 1003);
        final JournalEntryV2 readd = sign(owner, 4, heads(ban.computeHash()), JournalEntryV2.ACTION_ADD_MEMBER, mp(m.fp), 1004);
        final MembershipDag dag = new MembershipDag();
        for (final JournalEntryV2 e : new JournalEntryV2[]{g, prom, add, ban, readd}) dag.ingest(e.marshal());
        final MembershipDag.State st = dag.recompute(resolver());
        assertTrue(st.banned.contains(m.fpHex));
        assertFalse(st.members.contains(m.fpHex), "banned member must not be re-added");
    }

    @Test
    void concurrentRemoveBeatsPromote() {
        final Id owner = makeId(), a1 = makeId(), a2 = makeId(), x = makeId();
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 pa1 = sign(owner, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a1.fp), 1001);
        final JournalEntryV2 pa2 = sign(owner, 2, heads(pa1.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a2.fp), 1002);
        final JournalEntryV2 addx = sign(owner, 3, heads(pa2.computeHash()), JournalEntryV2.ACTION_ADD_MEMBER, mp(x.fp), 1003);
        final byte[] addxh = addx.computeHash();
        final JournalEntryV2 rem = sign(a1, 4, heads(addxh), JournalEntryV2.ACTION_REMOVE_MEMBER, mp(x.fp), 1004);
        final JournalEntryV2 promx = sign(a2, 4, heads(addxh), JournalEntryV2.ACTION_ADD_ADMIN, mp(x.fp), 1005);
        final MembershipDag dag = new MembershipDag();
        for (final JournalEntryV2 e : new JournalEntryV2[]{g, pa1, pa2, addx, rem, promx}) dag.ingest(e.marshal());
        final MembershipDag.State st = dag.recompute(resolver());
        assertFalse(st.members.contains(x.fpHex), "removal wins over concurrent promote (member)");
        assertFalse(st.admins.contains(x.fpHex), "removal wins over concurrent promote (admin)");
    }

    @Test
    void mutualAdminRemovalOneSurvives() {
        final Id owner = makeId(), a1 = makeId(), a2 = makeId();
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 pa1 = sign(owner, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a1.fp), 1001);
        final JournalEntryV2 pa2 = sign(owner, 2, heads(pa1.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a2.fp), 1002);
        final byte[] pa2h = pa2.computeHash();
        final JournalEntryV2 r12 = sign(a1, 3, heads(pa2h), JournalEntryV2.ACTION_REMOVE_ADMIN, mp(a2.fp), 1003);
        final JournalEntryV2 r21 = sign(a2, 3, heads(pa2h), JournalEntryV2.ACTION_REMOVE_ADMIN, mp(a1.fp), 1004);
        final MembershipDag dag = new MembershipDag();
        for (final JournalEntryV2 e : new JournalEntryV2[]{g, pa1, pa2, r12, r21}) dag.ingest(e.marshal());
        final MembershipDag.State st = dag.recompute(resolver());
        final int survivors = (st.admins.contains(a1.fpHex) ? 1 : 0) + (st.admins.contains(a2.fpHex) ? 1 : 0);
        assertEquals(1, survivors, "exactly one admin survives mutual removal");
        assertTrue(st.admins.contains(owner.fpHex));
    }

    @Test
    void convergenceIndependentOfOrder() {
        final Id owner = makeId(), a1 = makeId(), a2 = makeId(), x = makeId(), y = makeId();
        final JournalEntryV2 g = sign(owner, 0, heads(null), JournalEntryV2.ACTION_ADD_ADMIN, mp(owner.fp), 1000);
        final JournalEntryV2 pa1 = sign(owner, 1, heads(g.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a1.fp), 1001);
        final JournalEntryV2 pa2 = sign(owner, 2, heads(pa1.computeHash()), JournalEntryV2.ACTION_ADD_ADMIN, mp(a2.fp), 1002);
        final byte[] pa2h = pa2.computeHash();
        final JournalEntryV2 ax = sign(a1, 3, heads(pa2h), JournalEntryV2.ACTION_ADD_MEMBER, mp(x.fp), 1003);
        final JournalEntryV2 ay = sign(a2, 3, heads(pa2h), JournalEntryV2.ACTION_ADD_MEMBER, mp(y.fp), 1004);
        final JournalEntryV2[] all = {g, pa1, pa2, ax, ay};

        final MembershipDag d1 = new MembershipDag();
        for (final JournalEntryV2 e : all) d1.ingest(e.marshal());
        final MembershipDag.State s1 = d1.recompute(resolver());

        final MembershipDag d2 = new MembershipDag();
        for (int i = all.length - 1; i >= 0; i--) d2.ingest(all[i].marshal());
        final MembershipDag.State s2 = d2.recompute(resolver());

        assertEquals(s1.ownerFp, s2.ownerFp);
        assertEquals(s1.members, s2.members, "members converge regardless of ingest order");
        assertEquals(s1.admins, s2.admins, "admins converge regardless of ingest order");
        assertTrue(s1.members.contains(x.fpHex) && s1.members.contains(y.fpHex));
    }
}
