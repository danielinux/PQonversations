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
 * Trust Manifest v2 — head sign/verify round-trip and SNAPSHOT lifecycle (genesis /
 * confirmer append / revoke-by-rebuild). Behaviour MUST match the Vala client's v2 tests.
 */
class TrustManifestPhase2Test {

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
        byte[] dcHash() { return X3dhpqCrypto.sha512(dc.marshal()); } // v2: SHA-512
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

    /** Re-issue a subject device's DC under a new issuer DIK, keeping the subject DIK pubs. */
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

    /** Genesis entry: self-authored, AIK-signed. */
    private static TrustEntry genesis(Aik aik, Dev self) {
        return TrustEntry.signNew(TrustEntry.ACTION_ADD, self.id, self.dc,
                self.id, self.dcHash(), 0L, aik.edPriv, aik.mlPriv);
    }

    /** A member ADD authored by the genesis/publisher device (DC re-issued under its DIK). */
    private static TrustEntry memberAdd(Dev genesisDev, Dev member) {
        final DeviceCertificate reissued = reIssue(member, genesisDev.edPriv, genesisDev.mlPriv);
        member.dc = reissued; // reflect the DC as it appears in the snapshot
        return TrustEntry.signNew(TrustEntry.ACTION_ADD, member.id, reissued,
                genesisDev.id, genesisDev.dcHash(), 1L, genesisDev.edPriv, genesisDev.mlPriv);
    }

    /** Build a signed snapshot: genesis(self) + one member ADD per other dev, head under self DIK. */
    private static TrustManifest snapshot(Aik aik, Dev self, long version, byte[] prevHash, Dev... members) {
        final List<TrustEntry> es = new ArrayList<>();
        es.add(genesis(aik, self));
        for (final Dev mDev : members) {
            if (mDev.id == self.id) continue;
            es.add(memberAdd(self, mDev));
        }
        return new TrustManifest(version, prevHash, aik.pub, es, new byte[0], new byte[0])
                .signHead(self.edPriv, self.mlPriv);
    }

    // ---- §B: head sign/verify round-trip -----------------------------------

    @Test
    void headSignVerifyRoundTrip() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final List<TrustEntry> es = new ArrayList<>();
        es.add(genesis(aik, d1));
        final TrustManifest unsigned = new TrustManifest(1L, new byte[64], aik.pub, es, new byte[0], new byte[0]);

        final TrustManifest signed = unsigned.signHead(d1.edPriv, d1.mlPriv);
        assertTrue(signed.verifyHead(d1.edPub, d1.mlPub), "head verifies under the signer's DIK");

        final Dev other = issueDevice(9L, aik.edPriv, aik.mlPriv);
        assertFalse(signed.verifyHead(other.edPub, other.mlPub), "head fails under a different DIK");

        final TrustManifest re = TrustManifest.unmarshal(signed.marshal());
        assertNotNull(re);
        assertArrayEquals(signed.marshal(), re.marshal());
        assertTrue(re.verifyHead(d1.edPub, d1.mlPub));
    }

    // ---- §D1: migration / genesis snapshot round-trip ----------------------

    @Test
    void migrationGenesisRoundTrip() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);          // self / genesis
        final Dev d2 = issueDevice(2L, aik.edPriv, aik.mlPriv);          // originally under AIK

        final TrustManifest m = snapshot(aik, d1, 5L, new byte[64], d2); // d2 re-issued under d1 DIK

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(m);
        assertEquals(2, trusted.size());
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(2L));
        assertTrue(m.verifyHead(trusted.get(1L).getDikPubEd25519(), trusted.get(1L).getDikPubMLDSA()),
                "head signer d1 is a folded device");

        final TrustManifest re = TrustManifest.unmarshal(m.marshal());
        assertNotNull(re);
        assertEquals(2, TrustManifest.fold(re).size());
    }

    // ---- §D2: confirmer (primary) rebuilds the snapshot with the newcomer --

    @Test
    void confirmerAppendsAdd() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, aik.edPriv, aik.mlPriv);
        final TrustManifest m1 = snapshot(aik, d1, 5L, new byte[64], d2);
        assertEquals(2, TrustManifest.fold(m1).size());

        // Newcomer d3: the primary (d1) republishes a fresh snapshot {d1, d2, d3} at version+1.
        final Dev d3 = issueDevice(3L, d1.edPriv, d1.mlPriv);
        final TrustManifest m2 = snapshot(aik, d1, m1.getVersion() + 1L, m1.computeHash(), d2, d3);

        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(m2);
        assertEquals(3, trusted.size());
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(2L));
        assertTrue(trusted.containsKey(3L));
        assertTrue(m2.verifyHead(trusted.get(1L).getDikPubEd25519(), trusted.get(1L).getDikPubMLDSA()));
        assertArrayEquals(m1.computeHash(), m2.getPrevHash(), "prev_hash chains to the previous snapshot");
    }

    // ---- §D4: revoke = rebuild the snapshot WITHOUT the target -------------

    @Test
    void revokeRebuildsSnapshotWithoutTarget() {
        final Aik aik = new Aik();
        final Dev d1 = issueDevice(1L, aik.edPriv, aik.mlPriv);
        final Dev d2 = issueDevice(2L, aik.edPriv, aik.mlPriv);
        final Dev d3 = issueDevice(3L, aik.edPriv, aik.mlPriv);
        final TrustManifest m1 = snapshot(aik, d1, 5L, new byte[64], d2, d3);
        assertEquals(3, TrustManifest.fold(m1).size());

        // Revoke d2: republish a fresh snapshot asserting {d1, d3} only at version+1.
        final TrustManifest m2 = snapshot(aik, d1, m1.getVersion() + 1L, m1.computeHash(), d3);
        final Map<Long, DeviceCertificate> trusted = TrustManifest.fold(m2);
        assertEquals(2, trusted.size());
        assertTrue(trusted.containsKey(1L));
        assertTrue(trusted.containsKey(3L));
        assertFalse(trusted.containsKey(2L), "a revoked device is simply absent from the new snapshot");
    }
}
