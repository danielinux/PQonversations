// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import static org.junit.jupiter.api.Assertions.*;

import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Trust Manifest Phase 2 — head sign/verify round-trip, migration/genesis round-trip
 * (build a genesis manifest from a 2-device set → fold yields the same 2), and a
 * confirmer-append (a trusted non-genesis device appends an ADD → the new device shows
 * up in the fold). Behaviour MUST match the Vala client's Phase-2 tests.
 */
class TrustManifestPhase2Test {

    // ---- helpers (mirror TrustManifestFoldTest) ----------------------------

    private static final class Aik {
        final byte[] edPriv, edPub, mlPriv, mlPub;
        final AccountIdentityPub pub;
        Aik() {
            final KeyPair ed = X3dhpqCrypto.ed25519GenerateKeypair();
            final KeyPair ml = X3dhpqCrypto.mldsa65GenerateKeypair();
            this.edPriv = ed.priv; this.edPub = ed.pub;
            this.mlPriv = ml.priv; this.mlPub = ml.pub;
            this.pub = new AccountIdentityPub(edPub, mlPub);
        }
    }

    private static final class Dev {
        final long id;
        final byte[] edPriv, edPub, mlPriv, mlPub;
        DeviceCertificate dc;
        Dev(long id, byte[] edPriv, byte[] edPub, byte[] mlPriv, byte[] mlPub, DeviceCertificate dc) {
            this.id = id; this.edPriv = edPriv; this.edPub = edPub;
            this.mlPriv = mlPriv; this.mlPub = mlPub; this.dc = dc;
        }
        byte[] dcHash() { return X3dhpqCrypto.sha256(dc.marshal()); }
    }

    /** Fresh DIK keys; DC signed by the issuer's ed/ml priv keys (issuer = AIK or a device DIK). */
    private static Dev issueDevice(long id, byte[] issuerEdPriv, byte[] issuerMlPriv) {
        final KeyPair ed = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair x = X3dhpqCrypto.x25519GenerateKeypair();
        final KeyPair ml = X3dhpqCrypto.mldsa65GenerateKeypair();
        final DeviceCertificate unsigned =
                new DeviceCertificate(1, id, ed.pub, x.pub, ml.pub, 1000L, (byte) 0, new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(issuerEdPriv, sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(issuerMlPriv, sp);
        final DeviceCertificate dc =
                new DeviceCertificate(1, id, ed.pub, x.pub, ml.pub, 1000L, (byte) 0, sigEd, sigMl);
        return new Dev(id, ed.priv, ed.pub, ml.priv, ml.pub, dc);
    }

    /** Re-issue a subject device's DC under a new issuer DIK, keeping the same DIK pubs. */
    private static DeviceCertificate reIssue(Dev subject, byte[] issuerEdPriv, byte[] issuerMlPriv) {
        final DeviceCertificate unsigned = new DeviceCertificate(
                1, subject.id, subject.dc.getDikPubEd25519(), subject.dc.getDikPubX25519(),
                subject.dc.getDikPubMLDSA(), 2000L, (byte) 0, new byte[0], new byte[0]);
        final byte[] sp = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(issuerEdPriv, sp);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(issuerMlPriv, sp);
        return new DeviceCertificate(1, subject.id, subject.dc.getDikPubEd25519(),
                subject.dc.getDikPubX25519(), subject.dc.getDikPubMLDSA(), 2000L, (byte) 0, sigEd, sigMl);
    }

    private static List<byte[]> parents(byte[]... hs) {
        final List<byte[]> l = new ArrayList<>();
        for (final byte[] h : hs) if (h != null) l.add(h);
        return l;
    }

    // ---- §B: head sign/verify round-trip -----------------------------------

    @Test
    void headSignVerifyRoundTrip() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final TrustEntry g = TrustEntry.signNew(TrustEntry.ACTION_ADD, d1.id, d1.dc, 0L, parents(),
                d1.id, d1.dcHash(), 0L, aik.edPriv, aik.mlPriv);

        final List<TrustEntry> es = new ArrayList<>();
        es.add(g);
        final TrustManifest unsigned = new TrustManifest(1L, new byte[32], aik.pub, es, new byte[0], new byte[0]);

        final TrustManifest signed = unsigned.signHead(d1.edPriv, d1.mlPriv);
        assertTrue(signed.verifyHead(d1.edPub, d1.mlPub), "head verifies under the signer's DIK");

        // Wrong device DIK must fail.
        final Dev other = issueDevice(9L, aik.edPriv, aik.mlPriv);
        assertFalse(signed.verifyHead(other.edPub, other.mlPub), "head fails under a different DIK");

        // Marshal round-trip preserves the head signature.
        final TrustManifest re = TrustManifest.unmarshal(signed.marshal());
        assertNotNull(re);
        assertArrayEquals(signed.marshal(), re.marshal());
        assertTrue(re.verifyHead(d1.edPub, d1.mlPub));
    }

    // ---- §D1: migration / genesis round-trip -------------------------------

    /**
     * Primary (d1, holds AIK) builds a genesis manifest from a 2-device authorized set
     * {d1, d2}: genesis ADD(d1) AIK-signed; ADD(d2) with d2's DC re-issued under d1's DIK,
     * entry signed under d1's DIK; head signed under d1's DIK. Fold → {d1, d2}.
     */
    @Test
    void migrationGenesisRoundTrip() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);          // self DC under AIK
        final Dev d2 = issueDevice(2L, aik.edPriv, aik.mlPriv);          // originally under AIK

        // Genesis: self-authored, AIK-signed.
        final TrustEntry g = TrustEntry.signNew(TrustEntry.ACTION_ADD, d1.id, d1.dc, 0L, parents(),
                d1.id, d1.dcHash(), 0L, aik.edPriv, aik.mlPriv);

        // Re-issue d2's DC under the primary's (d1's) DIK, then append a DIK-signed ADD.
        d2.dc = reIssue(d2, d1.edPriv, d1.mlPriv);
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1L,
                parents(g.computeHash()), d1.id, d1.dcHash(), 1L, d1.edPriv, d1.mlPriv);

        final List<TrustEntry> es = new ArrayList<>();
        es.add(g);
        es.add(addD2);
        final TrustManifest m =
                new TrustManifest(5L, new byte[32], aik.pub, es, new byte[0], new byte[0])
                        .signHead(d1.edPriv, d1.mlPriv);

        // Head is signed by d1, which is in the fold.
        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(m);
        assertEquals(2, trusted.size());
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(2L));
        assertTrue(m.verifyHead(trusted.get(1L).getDikPubEd25519(), trusted.get(1L).getDikPubMLDSA()),
                "head signer d1 is a folded device");

        // Marshal/unmarshal round-trip preserves fold.
        final TrustManifest re = TrustManifest.unmarshal(m.marshal());
        assertNotNull(re);
        assertEquals(2, TrustManifest.fold(re).size());
    }

    // ---- §D2: confirmer-append ---------------------------------------------

    /**
     * From a migrated {d1,d2} manifest, a trusted non-genesis device (d2) confirms a new
     * device d3: d3's DC issued under d2's (confirmer's) DIK, entry signed under d2's DIK,
     * appended at the current heads. Fold → {d1, d2, d3}.
     */
    @Test
    void confirmerAppendsAdd() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, aik.edPriv, aik.mlPriv);

        final TrustEntry g = TrustEntry.signNew(TrustEntry.ACTION_ADD, d1.id, d1.dc, 0L, parents(),
                d1.id, d1.dcHash(), 0L, aik.edPriv, aik.mlPriv);
        d2.dc = reIssue(d2, d1.edPriv, d1.mlPriv);
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1L,
                parents(g.computeHash()), d1.id, d1.dcHash(), 1L, d1.edPriv, d1.mlPriv);

        final List<TrustEntry> es = new ArrayList<>();
        es.add(g);
        es.add(addD2);
        TrustManifest m = new TrustManifest(5L, new byte[32], aik.pub, es, new byte[0], new byte[0])
                .signHead(d1.edPriv, d1.mlPriv);

        // Confirmer = d2 (non-genesis, trusted). New device d3, DC under d2's DIK.
        final Dev d3 = issueDevice(3L, d2.edPriv, d2.mlPriv);
        final List<byte[]> heads = m.currentHeads();
        final long lam = m.nextLamport();
        final TrustEntry addD3 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d3.id, d3.dc, lam,
                heads, d2.id, d2.dcHash(), 2L, d2.edPriv, d2.mlPriv);

        final List<TrustEntry> es2 = new ArrayList<>(m.getEntries());
        es2.add(addD3);
        final byte[] prevHash = m.computeHash();
        final TrustManifest m2 =
                new TrustManifest(m.getVersion() + 1, prevHash, aik.pub, es2, new byte[0], new byte[0])
                        .signHead(d2.edPriv, d2.mlPriv); // confirmer (d2) publishes → signs head

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(m2);
        assertEquals(3, trusted.size());
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(2L));
        assertTrue(trusted.containsKey(3L));
        // Head signer (d2) is a folded device.
        assertTrue(m2.verifyHead(trusted.get(2L).getDikPubEd25519(), trusted.get(2L).getDikPubMLDSA()));
    }

    // ---- §D4: revoke via DIK-signed REMOVE by a trusted (non-genesis) device ----

    /**
     * Genesis d1 adds d2 (the revoker A) and d3 (the target B). A trusted NON-genesis
     * device (d2) authors a DIK-signed REMOVE of d3 → fold excludes d3. A concurrent
     * (non-descendant) re-ADD of d3 by d1 loses (removal-wins in TrustManifest.fold).
     */
    @Test
    void revokeByTrustedDeviceExcludesTarget() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);          // genesis / primary
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);            // A: the revoker
        final Dev d3 = issueDevice(3L, d1.edPriv, d1.mlPriv);            // B: the target
        final Dev d3b = issueDevice(3L, d1.edPriv, d1.mlPriv);          // fresh cert, same id, for re-add

        final TrustEntry g = TrustEntry.signNew(TrustEntry.ACTION_ADD, d1.id, d1.dc, 0L, parents(),
                d1.id, d1.dcHash(), 0L, aik.edPriv, aik.mlPriv);
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1L,
                parents(g.computeHash()), d1.id, d1.dcHash(), 1L, d1.edPriv, d1.mlPriv);
        final TrustEntry addD3 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d3.id, d3.dc, 2L,
                parents(addD2.computeHash()), d1.id, d1.dcHash(), 2L, d1.edPriv, d1.mlPriv);
        final byte[] head = addD3.computeHash();

        // Sanity: all three trusted before the revoke.
        final Map<Long, DeviceCertificate> before =
                TrustManifest.fold(manifest(aik, g, addD2, addD3));
        assertEquals(3, before.size());

        // d2 (trusted non-genesis) REMOVEs d3, carrying d3's current DC, signed under d2's DIK.
        final TrustEntry removeD3 = TrustEntry.signNew(TrustEntry.ACTION_REMOVE, d3.id, d3.dc, 3L,
                parents(head), d2.id, d2.dcHash(), 3L, d2.edPriv, d2.mlPriv);

        final Map<Long, DeviceCertificate> afterRevoke =
                TrustManifest.fold(manifest(aik, g, addD2, addD3, removeD3));
        assertEquals(2, afterRevoke.size(), "revoke excludes the target from the fold");
        assertTrue(afterRevoke.containsKey(1L));
        assertTrue(afterRevoke.containsKey(2L));
        assertFalse(afterRevoke.containsKey(3L), "revoked device B is no longer trusted");

        // Concurrent (non-descendant sibling of the REMOVE) re-ADD of d3 by d1 must lose.
        final TrustEntry reAddD3 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d3b.id, d3b.dc, 3L,
                parents(head), d1.id, d1.dcHash(), 4L, d1.edPriv, d1.mlPriv);
        final Map<Long, DeviceCertificate> afterConcurrentReadd =
                TrustManifest.fold(manifest(aik, g, addD2, addD3, removeD3, reAddD3));
        assertFalse(afterConcurrentReadd.containsKey(3L),
                "removal wins over a concurrent (non-descendant) re-add");
        assertEquals(2, afterConcurrentReadd.size());
    }

    private static TrustManifest manifest(Aik aik, TrustEntry... entries) {
        final List<TrustEntry> list = new ArrayList<>();
        for (final TrustEntry e : entries) list.add(e);
        return new TrustManifest(1L, new byte[32], aik.pub, list, new byte[0], new byte[0]);
    }
}
