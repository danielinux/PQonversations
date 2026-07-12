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
 * Trust Manifest Phase 1 — functional fold tests with REAL generated keys (actually sign
 * &amp; verify). Mirrors {@link DeviceDagTest}'s discipline; behaviour MUST match the Vala
 * client's tests/trust_manifest.vala.
 */
class TrustManifestFoldTest {

    // Account root: one AIK keypair.
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

    // A device: DIK keypairs + its issued DeviceCertificate (signed by its issuer).
    private static final class Dev {
        final long id;
        final byte[] edPriv, edPub, mlPriv, mlPub;
        final DeviceCertificate dc;
        Dev(long id, byte[] edPriv, byte[] edPub, byte[] mlPriv, byte[] mlPub, DeviceCertificate dc) {
            this.id = id; this.edPriv = edPriv; this.edPub = edPub;
            this.mlPriv = mlPriv; this.mlPub = mlPub; this.dc = dc;
        }
        byte[] dcHash() { return X3dhpqCrypto.sha256(dc.marshal()); }
    }

    // Issue a device: fresh DIK keys, DC signed by the issuer's ed/ml private keys.
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

    private static List<byte[]> parents(byte[]... hs) {
        final List<byte[]> l = new ArrayList<>();
        for (final byte[] h : hs) if (h != null) l.add(h);
        return l;
    }

    private static TrustManifest manifest(Aik aik, TrustEntry... entries) {
        final List<TrustEntry> list = new ArrayList<>();
        for (final TrustEntry e : entries) list.add(e);
        return new TrustManifest(1L, new byte[32], aik.pub, list, new byte[0], new byte[0]);
    }

    // Genesis entry: self-authored, AIK-signed.
    private static TrustEntry genesis(Aik aik, Dev d1) {
        return TrustEntry.signNew(TrustEntry.ACTION_ADD, d1.id, d1.dc, 0L, parents(),
                d1.id, d1.dcHash(), 0L, aik.edPriv, aik.mlPriv);
    }

    @Test
    void genesisPlusDelegatedAdd() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);           // DC under AIK
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);             // DC under D1's DIK

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1L,
                parents(g.computeHash()), d1.id, d1.dcHash(), 1L, d1.edPriv, d1.mlPriv);

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(manifest(aik, g, addD2));
        assertEquals(2, trusted.size());
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(2L));
    }

    @Test
    void untrustedAuthorDropped() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);
        // A rogue device NOT authorized in the DAG, with its own random DIK.
        final Dev rogue = issueDevice(99L, aik.edPriv, aik.mlPriv);
        final Dev d3 = issueDevice(3L, rogue.edPriv, rogue.mlPriv);

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1L,
                parents(g.computeHash()), d1.id, d1.dcHash(), 1L, d1.edPriv, d1.mlPriv);
        // Authored by rogue (99), which is not in trusted => must be dropped.
        final TrustEntry badAdd = TrustEntry.signNew(TrustEntry.ACTION_ADD, d3.id, d3.dc, 2L,
                parents(addD2.computeHash()), rogue.id, rogue.dcHash(), 2L, rogue.edPriv, rogue.mlPriv);

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(manifest(aik, g, addD2, badAdd));
        assertEquals(2, trusted.size(), "one bad entry is dropped, not fatal");
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(2L));
        assertFalse(trusted.containsKey(3L));
    }

    @Test
    void removalWinsOverSiblingReAdd() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);
        final Dev d2b = issueDevice(2L, d1.edPriv, d1.mlPriv); // fresh cert, same device id

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1L,
                parents(g.computeHash()), d1.id, d1.dcHash(), 1L, d1.edPriv, d1.mlPriv);
        final byte[] addD2h = addD2.computeHash();
        // Concurrent siblings on addD2: remove D2 vs re-add D2 with a fresh cert.
        final TrustEntry rem = TrustEntry.signNew(TrustEntry.ACTION_REMOVE, d2.id, d2.dc, 2L,
                parents(addD2h), d1.id, d1.dcHash(), 2L, d1.edPriv, d1.mlPriv);
        final TrustEntry readd = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2b.id, d2b.dc, 2L,
                parents(addD2h), d1.id, d1.dcHash(), 3L, d1.edPriv, d1.mlPriv);

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(manifest(aik, g, addD2, rem, readd));
        assertTrue(trusted.containsKey(1L));
        assertFalse(trusted.containsKey(2L), "removal wins over a concurrent (non-descendant) re-add");
        assertEquals(1, trusted.size());
    }

    @Test
    void convergenceUnderTwoInputOrders() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);
        final Dev d3 = issueDevice(3L, d2.edPriv, d2.mlPriv); // added by D2
        final Dev d4 = issueDevice(4L, d1.edPriv, d1.mlPriv); // added by D1

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc, 1L,
                parents(g.computeHash()), d1.id, d1.dcHash(), 1L, d1.edPriv, d1.mlPriv);
        final byte[] head = addD2.computeHash();
        // Two concurrent ADDs from the same head.
        final TrustEntry d2addsD3 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d3.id, d3.dc, 2L,
                parents(head), d2.id, d2.dcHash(), 2L, d2.edPriv, d2.mlPriv);
        final TrustEntry d1addsD4 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d4.id, d4.dc, 2L,
                parents(head), d1.id, d1.dcHash(), 3L, d1.edPriv, d1.mlPriv);

        final Map<Long, DeviceCertificate> a = TrustManifest.fold(manifest(aik, g, addD2, d2addsD3, d1addsD4));
        final Map<Long, DeviceCertificate> b = TrustManifest.fold(manifest(aik, d1addsD4, d2addsD3, addD2, g));
        assertEquals(a.keySet(), b.keySet(), "fold converges regardless of input order");
        assertTrue(a.containsKey(1L) && a.containsKey(2L) && a.containsKey(3L) && a.containsKey(4L));
    }

    @Test
    void roundTripBothTypes() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final TrustEntry g = genesis(aik, d1);

        final byte[] eWire = g.marshal();
        final TrustEntry e2 = TrustEntry.unmarshal(eWire);
        assertNotNull(e2);
        assertArrayEquals(eWire, e2.marshal());
        assertTrue(e2.verifyUnderAik(aik.pub), "genesis entry sig verifies under AIK");

        final TrustManifest m = manifest(aik, g);
        final byte[] mWire = m.marshal();
        final TrustManifest m2 = TrustManifest.unmarshal(mWire);
        assertNotNull(m2);
        assertArrayEquals(mWire, m2.marshal());
        assertEquals(1, TrustManifest.fold(m2).size());
    }
}
