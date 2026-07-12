// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import static org.junit.jupiter.api.Assertions.*;

import im.conversations.x3dhpq.crypto.X3dhpqCrypto;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Trust Manifest Phase 1 — layout KAT for {@link TrustManifest}. The asserted constant
 * is a regression lock and MUST match the Vala client byte-for-byte.
 */
class TrustManifestTest {

    // Fixed AIK from the canonical spec: pub_ed25519 = 32x0xD1, pub_mldsa = 1952x0xD2.
    static AccountIdentityPub aikVector() {
        final byte[] ed = new byte[32]; Arrays.fill(ed, (byte) 0xD1);
        final byte[] mldsa = new byte[1952]; Arrays.fill(mldsa, (byte) 0xD2);
        return new AccountIdentityPub(ed, mldsa);
    }

    // The TRUST_MANIFEST vector: version 7, zero prev_hash, aikVector, one entry with fixed dummy sigs.
    static TrustManifest manifestVector() {
        final byte[] entrySigEd = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
        final byte[] entrySigMl = {0x31, 0x32, 0x33};
        final TrustEntry entry = TrustEntryTest.trustEntryVector(entrySigEd, entrySigMl);
        final List<TrustEntry> entries = new ArrayList<>();
        entries.add(entry);
        final byte[] prevHash = new byte[32]; // 32 zero bytes
        return new TrustManifest(7L, prevHash, aikVector(), entries, new byte[0], new byte[0]);
    }

    // Computed value (locked): lowercase hex of SHA-256(signed_part).
    static final String TRUST_MANIFEST_SHA256_SIGNED_PART =
        "6385abed72f376d53951bde1aed581d4f272e7316bbd9b9e07cc0769c69282e7";

    @Test
    void sha256SignedPartVector() {
        final TrustManifest m = manifestVector();
        final String hex = TrustEntry.hex(X3dhpqCrypto.sha256(m.signedPart()));
        System.out.println("TRUST_MANIFEST sha256(signed_part) = " + hex);
        System.out.println("DC_SUBJECT.marshal().length = " + TrustEntryTest.dcSubject().marshal().length);
        assertEquals(TRUST_MANIFEST_SHA256_SIGNED_PART, hex);
    }

    @Test
    void marshalRoundtrip() {
        final byte[] sigEd = new byte[64]; Arrays.fill(sigEd, (byte) 0x41);
        final byte[] sigMl = new byte[3309]; Arrays.fill(sigMl, (byte) 0x42);
        final TrustManifest base = manifestVector();
        final TrustManifest m = new TrustManifest(base.getVersion(), base.getPrevHash(), base.getAik(),
                base.getEntries(), sigEd, sigMl);
        final byte[] wire = m.marshal();
        final TrustManifest m2 = TrustManifest.unmarshal(wire);
        assertNotNull(m2);
        assertArrayEquals(wire, m2.marshal(), "marshal->unmarshal->marshal is byte-stable");
        assertEquals(7L, m2.getVersion());
        assertEquals(1, m2.getEntries().size());
    }
}
