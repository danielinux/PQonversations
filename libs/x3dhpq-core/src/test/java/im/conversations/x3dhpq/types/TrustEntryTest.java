// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Trust Manifest Phase 1 — layout KAT for {@link TrustEntry}. The asserted constant is
 * a regression lock; it MUST match the Vala client's tests/trust_manifest.vala vector
 * byte-for-byte (that is the cross-language contract).
 */
class TrustEntryTest {

    // Fixed subject DeviceCertificate (DC_SUBJECT) from the canonical spec.
    static DeviceCertificate dcSubject() {
        final byte[] ed = new byte[32]; Arrays.fill(ed, (byte) 0xA1);
        final byte[] x = new byte[32]; Arrays.fill(x, (byte) 0xA2);
        final byte[] mldsa = new byte[0];
        final byte[] sigEd = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        final byte[] sigMl = {0x11, 0x12, 0x13, 0x14};
        return new DeviceCertificate(1, 0x22222222L, ed, x, mldsa, 1714483200L, (byte) 0x00, sigEd, sigMl);
    }

    // The TRUST_ENTRY vector object (unsigned — signed_part is signature-independent).
    static TrustEntry trustEntryVector(byte[] sigEd, byte[] sigMl) {
        final byte[] parent = new byte[32]; Arrays.fill(parent, (byte) 0xBB);
        final List<byte[]> parents = new ArrayList<>();
        parents.add(parent);
        final byte[] authorDcHash = new byte[32]; Arrays.fill(authorDcHash, (byte) 0xCC);
        return new TrustEntry(TrustEntry.ACTION_ADD, 0x22222222L, dcSubject(), 5L, parents,
                0x11111111L, authorDcHash, 0L, sigEd, sigMl);
    }

    // Computed value (locked). signed_part is independent of the signatures.
    static final String TRUST_ENTRY_SIGNED_PART =
        "5833444850512d5472757374456e7472792d763100" // "X3DHPQ-TrustEntry-v1\0"
      + "01"                                          // action = ADD
      + "22222222"                                    // device_id
      + "0065"                                        // dc_len = 101
      // DC_SUBJECT.marshal():
      + "0001"                                        //   version = 1
      + "22222222"                                    //   device_id
      + "0020" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1" // ed pub
      + "0020" + "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2" // x pub
      + "0000"                                        //   mldsa pub (empty)
      + "000000006630f000"                            //   created_at = 1714483200
      + "00"                                          //   flags
      + "0008" + "0102030405060708"                   //   sigEd
      + "0004" + "11121314"                           //   sigMl
      + "0000000000000005"                            // lamport = 5
      + "00000001"                                    // parent_count = 1
      + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // parents[0]
      + "11111111"                                    // author_device_id
      + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" // author_dc_hash
      + "0000000000000000";                           // timestamp

    @Test
    void signedPartVector() {
        final TrustEntry e = trustEntryVector(new byte[0], new byte[0]);
        final String hex = TrustEntry.hex(e.signedPart());
        System.out.println("TRUST_ENTRY signed_part = " + hex);
        assertEquals(TRUST_ENTRY_SIGNED_PART, hex);
    }

    @Test
    void marshalRoundtrip() {
        final byte[] sigEd = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26};
        final byte[] sigMl = {0x31, 0x32, 0x33};
        final TrustEntry e = trustEntryVector(sigEd, sigMl);
        final byte[] wire = e.marshal();
        final TrustEntry e2 = TrustEntry.unmarshal(wire);
        assertNotNull(e2);
        assertArrayEquals(wire, e2.marshal(), "marshal->unmarshal->marshal is byte-stable");
        assertEquals(TrustEntry.ACTION_ADD, e2.getAction());
        assertEquals(0x22222222L, e2.getDeviceId());
        assertEquals(5L, e2.getLamport());
        assertEquals(0x11111111L, e2.getAuthorDeviceId());
        assertEquals(1, e2.getParents().size());
    }
}
