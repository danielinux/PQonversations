// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class BundleTest {

    private AccountIdentityPub makeAik() {
        byte[] ed    = new byte[32];   Arrays.fill(ed, (byte) 0x01);
        byte[] mldsa = new byte[1952]; Arrays.fill(mldsa, (byte) 0xA5);
        return new AccountIdentityPub(ed, mldsa);
    }

    private DeviceCertificate makeCert() {
        byte[] ed  = new byte[32]; Arrays.fill(ed, (byte) 0x02);
        byte[] x   = new byte[32]; Arrays.fill(x,  (byte) 0x03);
        byte[] sig = new byte[64]; Arrays.fill(sig, (byte) 0xCC);
        return new DeviceCertificate(1, 0xDEADBEEFL, ed, x, null, 1714483200L, (byte) 0, sig, sig);
    }

    private Bundle.PublicSignedPreKey makeSpk() {
        byte[] pub = new byte[32]; Arrays.fill(pub, (byte) 0x04);
        byte[] sig = new byte[64]; Arrays.fill(sig, (byte) 0xDD);
        return new Bundle.PublicSignedPreKey(1, pub, sig);
    }

    @Test
    void testConstructAndAccessFields() {
        AccountIdentityPub aik = makeAik();
        DeviceCertificate cert = makeCert();
        Bundle.PublicSignedPreKey spk = makeSpk();

        List<Bundle.PublicKEMPreKey> kems = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            byte[] pub = new byte[1184]; Arrays.fill(pub, (byte)(i + 1));
            kems.add(new Bundle.PublicKEMPreKey(i + 1, pub));
        }

        List<Bundle.PublicOneTimePreKey> opks = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            byte[] pub = new byte[32]; Arrays.fill(pub, (byte)(i + 10));
            opks.add(new Bundle.PublicOneTimePreKey(i + 1, pub));
        }

        Bundle bundle = new Bundle(aik, cert, spk, kems, opks);

        assertTrue(aik.equals(bundle.getAikPub()));
        assertEquals(cert, bundle.getDeviceCert());
        assertEquals(1, bundle.getSignedPreKey().getId());
        assertEquals(5, bundle.getKemPreKeys().size());
        assertEquals(10, bundle.getOneTimePreKeys().size());
    }

    @Test
    void testNullAikAllowed() {
        // AIK may be absent on devices where only the public key is known
        Bundle bundle = new Bundle(null, makeCert(), makeSpk(), null, null);
        assertNull(bundle.getAikPub());
        assertEquals(0, bundle.getKemPreKeys().size());
        assertEquals(0, bundle.getOneTimePreKeys().size());
    }

    @Test
    void testNullCertRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new Bundle(null, null, makeSpk(), null, null));
    }

    @Test
    void testNullSpkRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> new Bundle(null, makeCert(), null, null, null));
    }

    @Test
    void testSpkMustHave32BytePub() {
        assertThrows(IllegalArgumentException.class,
                () -> new Bundle.PublicSignedPreKey(1, new byte[16], new byte[64]));
    }

    @Test
    void testOpkMustHave32BytePub() {
        assertThrows(IllegalArgumentException.class,
                () -> new Bundle.PublicOneTimePreKey(1, new byte[16]));
    }

    @Test
    void testKemKeyMustBeNonEmpty() {
        assertThrows(IllegalArgumentException.class,
                () -> new Bundle.PublicKEMPreKey(1, new byte[0]));
    }

    @Test
    void testDeviceListIsImmutable() {
        Bundle bundle = new Bundle(null, makeCert(), makeSpk(), null, null);
        assertThrows(UnsupportedOperationException.class,
                () -> bundle.getKemPreKeys().add(new Bundle.PublicKEMPreKey(99, new byte[]{0x01})));
    }
}
