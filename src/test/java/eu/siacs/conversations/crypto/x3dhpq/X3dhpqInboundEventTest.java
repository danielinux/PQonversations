package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Dc;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Cert;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Device;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

/**
 * Tests for X3dhpqService D3 inbound handlers: handleInboundBundle, handleInboundDeviceList.
 * Uses Robolectric so android.util.Log and Config are available without mocking.
 */
@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class X3dhpqInboundEventTest {

    // must match the fallback in X3dhpqService(X3dhpqDao) constructor path
    private static final String ACCOUNT_UUID = "test";
    private static final Jid PEER = Jid.of("peer@example.org");
    private static final int DEVICE_ID = 7777;

    // Shared AIK material generated once per class.
    private static KeyPair aikEdPair;
    private static KeyPair aikMlPair;
    private static AccountIdentityPub aip;
    private static byte[] aipMarshal;
    private static byte[] dcMarshal;   // valid, properly signed DC for DEVICE_ID

    @BeforeClass
    public static void generateKeyMaterial() {
        aikEdPair = X3dhpqCrypto.ed25519GenerateKeypair();
        aikMlPair = X3dhpqCrypto.mldsa65GenerateKeypair();
        aip = new AccountIdentityPub(aikEdPair.pub, aikMlPair.pub);
        aipMarshal = aip.marshal();
        dcMarshal = buildSignedDc(DEVICE_ID, aikEdPair, aikMlPair);
    }

    private LocalKeyBootstrapTest.FakeDao dao;
    private X3dhpqService service;

    @Before
    public void setUp() {
        dao = new LocalKeyBootstrapTest.FakeDao();
        service = new X3dhpqService(dao);
    }

    // ---- handleInboundBundle tests ----

    @Test
    public void tofuBundle_storesRowAndPinsAik() {
        final Bundle bundle = buildValidBundle(DEVICE_ID, aikEdPair, aikMlPair);
        service.handleInboundBundle(PEER, DEVICE_ID, bundle);

        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                dao.loadX3dhpqRemoteBundle(ACCOUNT_UUID, PEER.asBareJid().toString(), DEVICE_ID);
        Assert.assertNotNull("bundle row must be stored", row);
        Assert.assertArrayEquals("AIK must match", aipMarshal, row.aikPubMarshal());
        Assert.assertEquals("remoteBundleInserts must be 1", 1, dao.remoteBundleInserts);
    }

    @Test
    public void aikMismatch_refusesOverwrite() {
        // pre-populate with a different AIK
        final byte[] differentAip = buildDifferentAipMarshal();
        dao.putX3dhpqRemoteBundle(
                ACCOUNT_UUID, PEER.asBareJid().toString(), DEVICE_ID,
                differentAip, new byte[0], 1000L);

        final Bundle bundle = buildValidBundle(DEVICE_ID, aikEdPair, aikMlPair);
        service.handleInboundBundle(PEER, DEVICE_ID, bundle);

        // the row must still hold the original different AIK, not the new one
        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                dao.loadX3dhpqRemoteBundle(ACCOUNT_UUID, PEER.asBareJid().toString(), DEVICE_ID);
        Assert.assertNotNull("row must still exist", row);
        Assert.assertArrayEquals("AIK must not be overwritten", differentAip, row.aikPubMarshal());
        // inserts count must remain 1 (from our manual pre-populate)
        Assert.assertEquals("no new inserts after mismatch", 1, dao.remoteBundleInserts);
    }

    @Test
    public void badEdSignature_refusesPersist() {
        final Bundle bundle = buildBundleWithTamperedEdSig(DEVICE_ID, aikEdPair, aikMlPair);
        service.handleInboundBundle(PEER, DEVICE_ID, bundle);

        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                dao.loadX3dhpqRemoteBundle(ACCOUNT_UUID, PEER.asBareJid().toString(), DEVICE_ID);
        Assert.assertNull("nothing must be stored for bad Ed sig", row);
    }

    @Test
    public void badMldsaSignature_refusesPersist() {
        final Bundle bundle = buildBundleWithTamperedMldsaSig(DEVICE_ID, aikEdPair, aikMlPair);
        service.handleInboundBundle(PEER, DEVICE_ID, bundle);

        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                dao.loadX3dhpqRemoteBundle(ACCOUNT_UUID, PEER.asBareJid().toString(), DEVICE_ID);
        Assert.assertNull("nothing must be stored for bad ML-DSA sig", row);
    }

    @Test
    public void deviceIdMismatch_refusesPersist() {
        // DC is signed for DEVICE_ID but we claim it belongs to a different device
        final Bundle bundle = buildValidBundle(DEVICE_ID, aikEdPair, aikMlPair);
        service.handleInboundBundle(PEER, DEVICE_ID + 1, bundle);

        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                dao.loadX3dhpqRemoteBundle(ACCOUNT_UUID, PEER.asBareJid().toString(), DEVICE_ID + 1);
        Assert.assertNull("nothing stored when deviceId mismatches DC", row);
    }

    @Test
    public void incompleteBundle_noAikEd_refusesPersist() {
        final Bundle bundle = new Bundle();
        // no aik-ed25519, no aik-mldsa, no dc
        service.handleInboundBundle(PEER, DEVICE_ID, bundle);
        Assert.assertEquals("no inserts for incomplete bundle", 0, dao.remoteBundleInserts);
    }

    // ---- handleInboundDeviceList tests ----

    @Test
    public void inboundDeviceList_twoDevices_storesTwoRemoteDeviceRows() {
        final int id1 = 100;
        final int id2 = 200;
        final byte[] dc1 = buildSignedDc(id1, aikEdPair, aikMlPair);
        final byte[] dc2 = buildSignedDc(id2, aikEdPair, aikMlPair);

        final DeviceList list = buildDeviceList(new int[]{id1, id2}, new byte[][]{dc1, dc2});
        service.handleInboundDeviceList(PEER, list);

        final String peer = PEER.asBareJid().toString();
        Assert.assertEquals("two remote_device rows", 2, dao.remoteDeviceInserts);
        Assert.assertNotNull("device 100 stored", loadRemoteDevice(ACCOUNT_UUID, peer, id1));
        Assert.assertNotNull("device 200 stored", loadRemoteDevice(ACCOUNT_UUID, peer, id2));
    }

    @Test
    public void inboundDeviceList_malformedDc_skipped() {
        // one well-formed device, one with garbage DC bytes
        final int id1 = 300;
        final int id2 = 400;
        final byte[] dc1 = buildSignedDc(id1, aikEdPair, aikMlPair);
        final byte[] dcBad = new byte[]{0x00, 0x01}; // too short to parse

        final DeviceList list = buildDeviceList(new int[]{id1, id2}, new byte[][]{dc1, dcBad});
        service.handleInboundDeviceList(PEER, list);

        final String peer = PEER.asBareJid().toString();
        // only the valid device is stored
        Assert.assertEquals("only one remote_device row", 1, dao.remoteDeviceInserts);
        Assert.assertNotNull("device 300 stored", loadRemoteDevice(ACCOUNT_UUID, peer, id1));
        Assert.assertNull("device 400 not stored", loadRemoteDevice(ACCOUNT_UUID, peer, id2));
    }

    // ---- helpers ----

    private static byte[] buildSignedDc(int deviceId, KeyPair aikEd, KeyPair aikMl) {
        final KeyPair dikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair dikX = X3dhpqCrypto.x25519GenerateKeypair();
        final KeyPair dikMl = X3dhpqCrypto.mldsa65GenerateKeypair();
        final long now = System.currentTimeMillis() / 1000L;
        final DeviceCertificate unsigned = new DeviceCertificate(
                1, deviceId, dikEd.pub, dikX.pub, dikMl.pub, now,
                (byte) DeviceCertificate.FLAG_PRIMARY, null, null);
        // Sign signedPart() directly — no prefix. Matches Go + dino-fork.
        final byte[] input = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(aikEd.priv, input);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(aikMl.priv, input);
        final DeviceCertificate signed = new DeviceCertificate(
                1, deviceId, dikEd.pub, dikX.pub, dikMl.pub, now,
                (byte) DeviceCertificate.FLAG_PRIMARY, sigEd, sigMl);
        return signed.marshal();
    }

    private static Bundle buildValidBundle(int deviceId, KeyPair aikEd, KeyPair aikMl) {
        final byte[] dcBytes = buildSignedDc(deviceId, aikEd, aikMl);
        final Bundle bundle = new Bundle();
        final AikEd25519 aikEdEl = new AikEd25519();
        aikEdEl.setContent(aikEd.pub);
        bundle.addExtension(aikEdEl);
        final AikMldsa aikMlEl = new AikMldsa();
        aikMlEl.setContent(aikMl.pub);
        bundle.addExtension(aikMlEl);
        final Dc dcEl = new Dc();
        dcEl.setContent(dcBytes);
        bundle.addExtension(dcEl);
        return bundle;
    }

    private static Bundle buildBundleWithTamperedEdSig(int deviceId, KeyPair aikEd, KeyPair aikMl) {
        final byte[] dcBytes = buildSignedDc(deviceId, aikEd, aikMl);
        // tamper the last byte of the first Ed25519 signature byte
        final DeviceCertificate parsed = DeviceCertificate.unmarshal(dcBytes);
        final byte[] badSigEd = parsed.getSigEd25519();
        badSigEd[0] ^= 0xFF; // flip byte to corrupt
        final byte[] badDc = new DeviceCertificate(
                parsed.getVersion(), (int) parsed.getDeviceId(),
                parsed.getDikPubEd25519(), parsed.getDikPubX25519(), parsed.getDikPubMLDSA(),
                parsed.getCreatedAt(), parsed.getFlags(),
                badSigEd, parsed.getSigMLDSA()).marshal();
        final Bundle bundle = new Bundle();
        final AikEd25519 aikEdEl = new AikEd25519();
        aikEdEl.setContent(aikEd.pub);
        bundle.addExtension(aikEdEl);
        final AikMldsa aikMlEl = new AikMldsa();
        aikMlEl.setContent(aikMl.pub);
        bundle.addExtension(aikMlEl);
        final Dc dcEl = new Dc();
        dcEl.setContent(badDc);
        bundle.addExtension(dcEl);
        return bundle;
    }

    private static Bundle buildBundleWithTamperedMldsaSig(int deviceId, KeyPair aikEd, KeyPair aikMl) {
        final byte[] dcBytes = buildSignedDc(deviceId, aikEd, aikMl);
        final DeviceCertificate parsed = DeviceCertificate.unmarshal(dcBytes);
        final byte[] badSigMl = parsed.getSigMLDSA();
        badSigMl[0] ^= 0xFF;
        final byte[] badDc = new DeviceCertificate(
                parsed.getVersion(), (int) parsed.getDeviceId(),
                parsed.getDikPubEd25519(), parsed.getDikPubX25519(), parsed.getDikPubMLDSA(),
                parsed.getCreatedAt(), parsed.getFlags(),
                parsed.getSigEd25519(), badSigMl).marshal();
        final Bundle bundle = new Bundle();
        final AikEd25519 aikEdEl = new AikEd25519();
        aikEdEl.setContent(aikEd.pub);
        bundle.addExtension(aikEdEl);
        final AikMldsa aikMlEl = new AikMldsa();
        aikMlEl.setContent(aikMl.pub);
        bundle.addExtension(aikMlEl);
        final Dc dcEl = new Dc();
        dcEl.setContent(badDc);
        bundle.addExtension(dcEl);
        return bundle;
    }

    private static byte[] buildDifferentAipMarshal() {
        final KeyPair ed = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair ml = X3dhpqCrypto.mldsa65GenerateKeypair();
        return new AccountIdentityPub(ed.pub, ml.pub).marshal();
    }

    private static DeviceList buildDeviceList(int[] ids, byte[][] dcs) {
        final DeviceList list = new DeviceList();
        list.setVersion("1");
        for (int i = 0; i < ids.length; i++) {
            final Device d = new Device();
            d.setDeviceId(ids[i]);
            d.setFlags("1");
            final Cert cert = new Cert();
            cert.setContent(dcs[i]);
            d.setCert(cert);
            list.addDevice(d);
        }
        return list;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    // Load a remote device row from the fake DAO by accountUuid/peer/deviceId.
    private DatabaseBackend.X3dhpqRemoteDeviceRow loadRemoteDevice(
            String accountUuid, String peer, int deviceId) {
        for (final DatabaseBackend.X3dhpqRemoteDeviceRow r :
                dao.listX3dhpqRemoteDevices(accountUuid, peer)) {
            if (r.deviceId() == deviceId) return r;
        }
        return null;
    }
}
