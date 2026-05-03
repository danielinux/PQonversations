package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.persistance.DatabaseBackend;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityKey;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for X3dhpqStanzaBuilder.
 * Uses a pure-Java fake DAO; no Android runtime needed.
 */
public class X3dhpqStanzaBuilderTest {

    private static final String UUID = "test-account-uuid";
    private static final int DEVICE_ID = 12345;

    // Shared DAO populated once per test class.
    private static LocalKeyBootstrapTest.FakeDao dao;

    // Keep original bytes for round-trip assertions.
    private static byte[] aikPubEd25519;
    private static byte[] dcMarshal;

    @BeforeClass
    public static void setup() {
        dao = new LocalKeyBootstrapTest.FakeDao();

        // Generate AIK (Ed25519 + ML-DSA-65)
        final KeyPair aikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair aikMl = X3dhpqCrypto.mldsa65GenerateKeypair();
        aikPubEd25519 = aikEd.pub;

        final AccountIdentityPub aip = new AccountIdentityPub(aikEd.pub, aikMl.pub);
        final AccountIdentityKey aik = new AccountIdentityKey(aikEd.priv, aikMl.priv, aip);
        final String fingerprint = aip.fingerprint(X3dhpqCrypto.BLAKE2B_160);
        dao.putX3dhpqAccountIdentity(UUID, aik.marshal(), aip.marshal(), fingerprint);

        // Generate DIK
        final KeyPair dikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair dikX = X3dhpqCrypto.x25519GenerateKeypair();
        final KeyPair dikMl = X3dhpqCrypto.mldsa65GenerateKeypair();
        final DeviceIdentityKey dik =
                new DeviceIdentityKey(
                        dikEd.priv, dikEd.pub,
                        dikX.priv, dikX.pub,
                        dikMl.priv, dikMl.pub);

        // Generate and sign DC
        final long createdAt = System.currentTimeMillis() / 1000L;
        final DeviceCertificate unsignedDc =
                new DeviceCertificate(
                        1, DEVICE_ID,
                        dikEd.pub, dikX.pub, dikMl.pub,
                        createdAt, (byte) DeviceCertificate.FLAG_PRIMARY,
                        null, null);
        final byte[] signedPart = unsignedDc.signedPart();
        final byte[] dcInput = concat(DeviceCertificate.SIGNING_PREFIX, signedPart);
        final byte[] dcSigEd = X3dhpqCrypto.ed25519Sign(aikEd.priv, dcInput);
        final byte[] dcSigMl = X3dhpqCrypto.mldsa65Sign(aikMl.priv, dcInput);
        final DeviceCertificate dc =
                new DeviceCertificate(
                        1, DEVICE_ID,
                        dikEd.pub, dikX.pub, dikMl.pub,
                        createdAt, (byte) DeviceCertificate.FLAG_PRIMARY,
                        dcSigEd, dcSigMl);
        dcMarshal = dc.marshal();

        dao.putX3dhpqLocalDevice(UUID, DEVICE_ID, dik.marshal(), dcMarshal, createdAt, DeviceCertificate.FLAG_PRIMARY);

        // Generate SPK
        final KeyPair spk = X3dhpqCrypto.x25519GenerateKeypair();
        final byte[] spkSigEd = X3dhpqCrypto.ed25519Sign(dikEd.priv, spk.pub);
        final byte[] spkSigMl = X3dhpqCrypto.mldsa65Sign(dikMl.priv, spk.pub);
        dao.putX3dhpqSignedPreKey(UUID, 1, spk.pub, spk.priv, spkSigEd, spkSigMl, createdAt);

        // 2 KEM pre-keys
        for (int i = 1; i <= 2; i++) {
            final KemKeyPair kem = X3dhpqCrypto.mlkem768GenerateKeypair();
            dao.putX3dhpqKemPreKey(UUID, i, kem.pub, kem.priv);
        }

        // 2 OPKs
        for (int i = 1; i <= 2; i++) {
            final KeyPair opk = X3dhpqCrypto.x25519GenerateKeypair();
            dao.putX3dhpqOneTimePreKey(UUID, i, opk.pub, opk.priv);
        }
    }

    @Test
    public void buildDeviceList_hasCorrectStructure() {
        final DeviceList list = X3dhpqStanzaBuilder.buildDeviceList(dao, UUID);

        Assert.assertEquals("version must be 1", "1", list.getVersion());
        Assert.assertNotNull("issued-at must be set", list.getIssuedAt());

        final var devices = list.getDevices();
        Assert.assertEquals("exactly one device", 1, devices.size());

        final var device = devices.iterator().next();
        Assert.assertEquals("device id must match", DEVICE_ID, (int) device.getDeviceId());
        Assert.assertNotNull("device must have a cert child", device.getCert());

        // cert content must decode back to the original DC marshal bytes
        final byte[] certBytes = device.getCert().asBytes();
        Assert.assertArrayEquals("cert must round-trip to original DC bytes", dcMarshal, certBytes);
    }

    @Test
    public void buildDeviceList_dcDecodesCorrectDeviceId() {
        final DeviceList list = X3dhpqStanzaBuilder.buildDeviceList(dao, UUID);
        final byte[] certBytes = list.getDevices().iterator().next().getCert().asBytes();
        final DeviceCertificate parsed = DeviceCertificate.unmarshal(certBytes);
        Assert.assertEquals("DC device-id must match", DEVICE_ID, parsed.getDeviceId());
    }

    @Test
    public void buildBundle_hasRequiredElements() {
        final Bundle bundle = X3dhpqStanzaBuilder.buildBundle(dao, UUID, DEVICE_ID);

        Assert.assertNotNull("aik-ed25519 must be present", bundle.getAikEd25519());
        Assert.assertNotNull("aik-mldsa must be present", bundle.getAikMldsa());
        Assert.assertNotNull("dc must be present", bundle.getDc());
        Assert.assertNotNull("dik-ed25519 must be present", bundle.getDikEd25519());
        Assert.assertNotNull("ik must be present", bundle.getIk());
        Assert.assertNotNull("dik-mldsa must be present", bundle.getDikMldsa());
        Assert.assertNotNull("spk must be present", bundle.getSpk());
        Assert.assertNotNull("kemkeys must be present", bundle.getKemkeys());
        Assert.assertNotNull("opks must be present", bundle.getOpks());
    }

    @Test
    public void buildBundle_aikEd25519MatchesOriginal() {
        final Bundle bundle = X3dhpqStanzaBuilder.buildBundle(dao, UUID, DEVICE_ID);
        final byte[] decoded = bundle.getAikEd25519().asBytes();
        Assert.assertArrayEquals(
                "aik-ed25519 must round-trip to original 32-byte Ed25519 pub",
                aikPubEd25519,
                decoded);
    }

    @Test
    public void buildBundle_kemkeysCount() {
        final Bundle bundle = X3dhpqStanzaBuilder.buildBundle(dao, UUID, DEVICE_ID);
        Assert.assertEquals("must have 2 kemkeys", 2, bundle.getKemkeys().getKemkeys().size());
    }

    @Test
    public void buildBundle_opksCount() {
        final Bundle bundle = X3dhpqStanzaBuilder.buildBundle(dao, UUID, DEVICE_ID);
        Assert.assertEquals("must have 2 opks", 2, bundle.getOpks().getOpks().size());
    }

    @Test
    public void buildBundle_spkHasKeyAndSig() {
        final Bundle bundle = X3dhpqStanzaBuilder.buildBundle(dao, UUID, DEVICE_ID);
        final var spk = bundle.getSpk();
        Assert.assertEquals("spk id must be 1", Integer.valueOf(1), spk.getId());
        Assert.assertNotNull("spk must have a key child", spk.getKey());
        Assert.assertNotNull("spk must have a sig child", spk.getSig());
        Assert.assertTrue("spk key must be non-empty", spk.getKey().asBytes().length > 0);
        Assert.assertTrue("spk sig must be non-empty", spk.getSig().asBytes().length > 0);
    }

    @Test
    public void buildBundle_dcMatchesOriginal() {
        final Bundle bundle = X3dhpqStanzaBuilder.buildBundle(dao, UUID, DEVICE_ID);
        Assert.assertArrayEquals(
                "dc in bundle must match original DC bytes",
                dcMarshal,
                bundle.getDc().asBytes());
    }

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
