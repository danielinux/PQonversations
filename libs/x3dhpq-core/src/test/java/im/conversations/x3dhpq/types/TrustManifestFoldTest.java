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
 * Trust Manifest v2 — functional SNAPSHOT fold tests with REAL generated keys (actually
 * sign &amp; verify). Behaviour MUST match the Vala client's tests/trust_manifest.vala v2.
 *
 * <p>v2 fold: one genesis (self-authored, AIK-signed) + ADD entries authored by the genesis
 * device, ordered by device_id. No lamport/parents/topo-sort, no REMOVE/removal-wins — a
 * revoked device is simply absent from the snapshot.
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
        byte[] dcHash() { return X3dhpqCrypto.sha512(dc.marshal()); } // v2: SHA-512
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

    private static TrustManifest manifest(Aik aik, TrustEntry... entries) {
        final List<TrustEntry> list = new ArrayList<>();
        for (final TrustEntry e : entries) list.add(e);
        return new TrustManifest(1L, new byte[64], aik.pub, list, new byte[0], new byte[0]);
    }

    // Genesis entry: self-authored, AIK-signed.
    private static TrustEntry genesis(Aik aik, Dev d1) {
        return TrustEntry.signNew(TrustEntry.ACTION_ADD, d1.id, d1.dc,
                d1.id, d1.dcHash(), 0L, aik.edPriv, aik.mlPriv);
    }

    // A member ADD authored by the genesis device (signed under its DIK).
    private static TrustEntry memberAdd(Dev genesisDev, Dev member) {
        return TrustEntry.signNew(TrustEntry.ACTION_ADD, member.id, member.dc,
                genesisDev.id, genesisDev.dcHash(), 1L, genesisDev.edPriv, genesisDev.mlPriv);
    }

    @Test
    void genesisPlusDelegatedAdd() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);           // DC under AIK
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);             // DC re-issued under D1's DIK

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD2 = memberAdd(d1, d2);

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
        // A rogue device NOT the genesis, with its own random DIK.
        final Dev rogue = issueDevice(99L, aik.edPriv, aik.mlPriv);
        final Dev d3 = issueDevice(3L, rogue.edPriv, rogue.mlPriv);

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD2 = memberAdd(d1, d2);
        // Authored by rogue (99), which is NOT the genesis device => must be dropped.
        final TrustEntry badAdd = TrustEntry.signNew(TrustEntry.ACTION_ADD, d3.id, d3.dc,
                rogue.id, rogue.dcHash(), 2L, rogue.edPriv, rogue.mlPriv);

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(manifest(aik, g, addD2, badAdd));
        assertEquals(2, trusted.size(), "one bad (non-genesis-authored) entry is dropped, not fatal");
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(2L));
        assertFalse(trusted.containsKey(3L));
    }

    @Test
    void wrongAuthorDcHashDropped() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);

        final TrustEntry g = genesis(aik, d1);
        // Author is the genesis (d1) and the sig verifies, but author_dc_hash is wrong (64x0x00).
        final TrustEntry addD2 = TrustEntry.signNew(TrustEntry.ACTION_ADD, d2.id, d2.dc,
                d1.id, new byte[64], 1L, d1.edPriv, d1.mlPriv);

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(manifest(aik, g, addD2));
        assertEquals(1, trusted.size(), "author_dc_hash mismatch drops the entry");
        assertTrue(trusted.containsKey(1L));
        assertFalse(trusted.containsKey(2L));
    }

    @Test
    void revokedDeviceAbsentFromSnapshot() {
        // v2 has no REMOVE — revoking d2 just means it is not in the republished snapshot.
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d3 = issueDevice(3L, d1.edPriv, d1.mlPriv);

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD3 = memberAdd(d1, d3); // d2 simply omitted

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(manifest(aik, g, addD3));
        assertEquals(2, trusted.size());
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(3L));
        assertFalse(trusted.containsKey(2L), "a revoked device is simply absent from the snapshot");
    }

    @Test
    void convergenceUnderTwoInputOrders() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, d1.edPriv, d1.mlPriv);
        final Dev d3 = issueDevice(3L, d1.edPriv, d1.mlPriv);
        final Dev d4 = issueDevice(4L, d1.edPriv, d1.mlPriv);

        final TrustEntry g = genesis(aik, d1);
        final TrustEntry addD2 = memberAdd(d1, d2);
        final TrustEntry addD3 = memberAdd(d1, d3);
        final TrustEntry addD4 = memberAdd(d1, d4);

        final Map<Long, DeviceCertificate> a = TrustManifest.fold(manifest(aik, g, addD2, addD3, addD4));
        final Map<Long, DeviceCertificate> b = TrustManifest.fold(manifest(aik, addD4, addD2, g, addD3));
        assertEquals(a.keySet(), b.keySet(), "fold converges regardless of input order (sorted by device_id)");
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
