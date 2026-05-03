// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.Arrays;

class AccountIdentityPubTest {

    private static final InlineBlake2b160 HASHER = new InlineBlake2b160();

    @Test
    void blake2bEmptyStringKnownAnswer() {
        // Sanity-check the inline hasher: BLAKE2b-160("") must equal the known vector.
        byte[] digest = InlineBlake2b160.blake2b160(new byte[0]);
        String hex = AppendixAValidator.bytesToHex(digest);
        // Vector verified: b2sum -l 160 /dev/null and python3 hashlib blake2b digest_size=20
        Assertions.assertEquals("3345524abf6bbe1809449224b5972c41790b6cf2", hex,
                "BLAKE2b-160 of empty string");
    }

    @Test
    void testVectorA1Fingerprint() {
        // A.1 vector: PubEd25519 = 0x01..0x20, PubMLDSA = 0xA5 x 1952
        byte[] pubEd = new byte[32];
        for (int i = 0; i < 32; i++) pubEd[i] = (byte) (0x01 + i);
        byte[] pubMLDSA = new byte[1952];
        Arrays.fill(pubMLDSA, (byte) 0xA5);

        AccountIdentityPub aip = new AccountIdentityPub(pubEd, pubMLDSA);
        String fp = aip.fingerprint(HASHER);
        Assertions.assertEquals("7AD37 1A1A3 67A62 B6533 1BC5A 2204C", fp,
                "A.1 AIK fingerprint must match test vector");
    }

    @Test
    void marshalUnmarshalRoundtrip() {
        byte[] pubEd = new byte[32];
        for (int i = 0; i < 32; i++) pubEd[i] = (byte) (i + 1);
        byte[] pubMLDSA = new byte[1952];
        Arrays.fill(pubMLDSA, (byte) 0x3C);

        AccountIdentityPub original = new AccountIdentityPub(pubEd, pubMLDSA);
        byte[] wire = original.marshal();
        Assertions.assertEquals(1987, wire.length, "marshal() must produce 1987 bytes");

        AccountIdentityPub recovered = AccountIdentityPub.unmarshal(wire);
        Assertions.assertTrue(original.equals(recovered), "unmarshal(marshal(x)) must equal x");
    }
}
