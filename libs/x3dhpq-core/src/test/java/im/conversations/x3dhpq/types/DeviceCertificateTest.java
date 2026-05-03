// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.Arrays;

class DeviceCertificateTest {

    // A.2 expected hex (from testvectors_test.go)
    private static final String WANT_SIGNED_PART_HEX =
            "0001" + "deadbeef" +
            "0020" + "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
            "0020" + "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40" +
            "0000" +
            "000000006630f000" +
            "01";

    @Test
    void testVectorA2SignedPart() {
        byte[] dikEd = new byte[32];
        for (int i = 0; i < 32; i++) dikEd[i] = (byte) (0x01 + i);
        byte[] dikX = new byte[32];
        for (int i = 0; i < 32; i++) dikX[i] = (byte) (0x21 + i);

        DeviceCertificate dc = new DeviceCertificate(
                1,
                0xDEADBEEFL,
                dikEd,
                dikX,
                null,
                1714483200L,
                (byte) 0x01,
                null,
                null);

        String got = AppendixAValidator.bytesToHex(dc.signedPart());
        Assertions.assertEquals(WANT_SIGNED_PART_HEX, got,
                "A.2 DeviceCertificate.signedPart() must match test vector");
    }

    @Test
    void testMarshalUnmarshalRoundtrip() {
        byte[] dikEd = new byte[32];
        for (int i = 0; i < 32; i++) dikEd[i] = (byte) (i + 1);
        byte[] dikX = new byte[32];
        Arrays.fill(dikX, (byte) 0xAB);
        byte[] dikMLDSA = new byte[1952];
        Arrays.fill(dikMLDSA, (byte) 0x7F);
        // dummy Ed25519 sig: 64 bytes
        byte[] sigEd = new byte[64];
        Arrays.fill(sigEd, (byte) 0xCC);
        // dummy ML-DSA sig: 3309 bytes
        byte[] sigMLDSA = new byte[3309];
        Arrays.fill(sigMLDSA, (byte) 0xDD);

        DeviceCertificate original = new DeviceCertificate(
                1, 0x12345678L,
                dikEd, dikX, dikMLDSA,
                1714483200L, (byte) DeviceCertificate.FLAG_PRIMARY,
                sigEd, sigMLDSA);

        byte[] wire = original.marshal();
        DeviceCertificate recovered = DeviceCertificate.unmarshal(wire);

        Assertions.assertEquals(original, recovered,
                "unmarshal(marshal(dc)) must equal dc");
    }
}
