package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Dc;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Ik;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkeys;
import im.conversations.android.xmpp.model.x3dhpq.bundle.KemMldsaSig;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Spk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkKey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkSig;
import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Cert;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.Device;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
    public void badKemSignature_refusesPersist() {
        final Bundle bundle = buildBundleWithTamperedKemSig(DEVICE_ID, aikEdPair, aikMlPair);
        service.handleInboundBundle(PEER, DEVICE_ID, bundle);

        final DatabaseBackend.X3dhpqRemoteBundleRow row =
                dao.loadX3dhpqRemoteBundle(ACCOUNT_UUID, PEER.asBareJid().toString(), DEVICE_ID);
        Assert.assertNull("nothing must be stored for bad KEM sig", row);
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

    // ---- signed devicelist gate (§8.2/§8.5) ----

    @Test
    public void inboundSignedDeviceList_acceptsAndRejectsRollback() {
        final String peer = PEER.asBareJid().toString();
        final long now = System.currentTimeMillis() / 1000L;
        // Pin the peer AIK by seeding a cached bundle (resolvePinnedPeerAik path).
        dao.putX3dhpqRemoteDevice(ACCOUNT_UUID, peer, DEVICE_ID, dcMarshal, now);
        dao.putX3dhpqRemoteBundle(ACCOUNT_UUID, peer, DEVICE_ID, aipMarshal, new byte[] {0x01}, now);

        final long addedAt = now - 1000L;
        final DeviceList v5 = buildSignedDeviceList(
                5L, now, DEVICE_ID, dcMarshal, addedAt, (byte) 1, aikEdPair, aikMlPair);
        service.handleInboundDeviceList(PEER, v5);

        final DatabaseBackend.X3dhpqDeviceListStateRow st =
                dao.loadX3dhpqDeviceListState(ACCOUNT_UUID, peer);
        Assert.assertNotNull("signed list must persist devicelist state", st);
        Assert.assertEquals("version 5 accepted", 5L, st.version());
        Assert.assertTrue("acceptedSigned flips true", st.acceptedSigned());

        // A lower-version (rollback) list from the same signer MUST be rejected;
        // the persisted state stays at version 5.
        final DeviceList v3 = buildSignedDeviceList(
                3L, now, DEVICE_ID, dcMarshal, addedAt, (byte) 1, aikEdPair, aikMlPair);
        service.handleInboundDeviceList(PEER, v3);
        Assert.assertEquals("rollback rejected — version unchanged",
                5L, dao.loadX3dhpqDeviceListState(ACCOUNT_UUID, peer).version());

        // A tampered signature MUST be rejected too.
        final DeviceList v6bad = buildSignedDeviceList(
                6L, now, DEVICE_ID, dcMarshal, addedAt, (byte) 1, aikEdPair, aikMlPair);
        v6bad.getSig().setContent(new byte[64]); // zeroed Ed25519 sig
        service.handleInboundDeviceList(PEER, v6bad);
        Assert.assertEquals("bad-signature list rejected — version unchanged",
                5L, dao.loadX3dhpqDeviceListState(ACCOUNT_UUID, peer).version());
    }

    // ---- helpers ----

    // Independent (test-side) implementation of the §8.3 layout-A SignedPart:
    // "X3DHPQ-DeviceList-v1\0"(21) || u64 version || i64 issued_at ||
    //   per device sorted by id asc: u32 id || i64 added_at || u8 flags || u32 cert_len || cert.
    // NO num_devices / version_marker — mirrors the Dino fork byte-for-byte.
    private static byte[] deviceListSignedPartA(
            long version, long issuedAt, int deviceId, byte[] cert, long addedAt, byte flags) {
        final byte[] label =
                "X3DHPQ-DeviceList-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII); // 20 bytes
        final byte[] prefix = new byte[21]; // label + trailing 0x00 domain-separator
        System.arraycopy(label, 0, prefix, 0, 20);
        final ByteBuffer buf =
                ByteBuffer.allocate(prefix.length + 8 + 8 + 4 + 8 + 1 + 4 + cert.length)
                        .order(ByteOrder.BIG_ENDIAN);
        buf.put(prefix);
        buf.putLong(version);
        buf.putLong(issuedAt);
        buf.putInt(deviceId);
        buf.putLong(addedAt);
        buf.put(flags);
        buf.putInt(cert.length);
        buf.put(cert);
        return buf.array();
    }

    private static DeviceList buildSignedDeviceList(
            long version, long issuedAt, int deviceId, byte[] cert, long addedAt, byte flags,
            KeyPair aikEd, KeyPair aikMl) {
        final DeviceList list = new DeviceList();
        list.setVersion(Long.toUnsignedString(version));
        list.setIssuedAt(Long.toString(issuedAt));
        final Device d = new Device();
        d.setDeviceId(deviceId);
        d.setAddedAt(addedAt);
        d.setFlags(Integer.toString(flags & 0xff));
        final Cert certEl = new Cert();
        certEl.setContent(cert);
        d.setCert(certEl);
        list.addDevice(d);
        final byte[] sp = deviceListSignedPartA(version, issuedAt, deviceId, cert, addedAt, flags);
        list.setSig(X3dhpqCrypto.ed25519Sign(aikEd.priv, sp));
        list.setMldsaSig(X3dhpqCrypto.mldsa65Sign(aikMl.priv, sp));
        return list;
    }

    // Sign a DC for a caller-supplied DIK so the same DIK can also sign the
    // bundle's SPK and KEM pre-keys (needed now that handleInboundBundle verifies
    // those against DeviceCert.DIKPub*).
    private static byte[] signedDc(
            int deviceId, KeyPair aikEd, KeyPair aikMl,
            KeyPair dikEd, KeyPair dikX, KeyPair dikMl) {
        final long now = System.currentTimeMillis() / 1000L;
        final DeviceCertificate unsigned = new DeviceCertificate(
                1, deviceId, dikEd.pub, dikX.pub, dikMl.pub, now,
                (byte) DeviceCertificate.FLAG_PRIMARY, null, null);
        // Sign signedPart() directly — no prefix. Matches Go + dino-fork.
        final byte[] input = unsigned.signedPart();
        final byte[] sigEd = X3dhpqCrypto.ed25519Sign(aikEd.priv, input);
        final byte[] sigMl = X3dhpqCrypto.mldsa65Sign(aikMl.priv, input);
        return new DeviceCertificate(
                1, deviceId, dikEd.pub, dikX.pub, dikMl.pub, now,
                (byte) DeviceCertificate.FLAG_PRIMARY, sigEd, sigMl).marshal();
    }

    private static byte[] buildSignedDc(int deviceId, KeyPair aikEd, KeyPair aikMl) {
        return signedDc(
                deviceId, aikEd, aikMl,
                X3dhpqCrypto.ed25519GenerateKeypair(),
                X3dhpqCrypto.x25519GenerateKeypair(),
                X3dhpqCrypto.mldsa65GenerateKeypair());
    }

    // A complete, correctly-signed bundle: DC (AIK-signed) binding the DIK, plus
    // ik, a DIK-signed SPK, and a hybrid-DIK-signed KEM pre-key (spec §9.1).
    private static Bundle buildValidBundle(int deviceId, KeyPair aikEd, KeyPair aikMl) {
        return buildBundle(deviceId, aikEd, aikMl, true);
    }

    // Same as buildValidBundle but the KEM pre-key's Ed25519 signature is made by
    // a foreign key, so it must fail verification against the DC's DIK.
    private static Bundle buildBundleWithTamperedKemSig(int deviceId, KeyPair aikEd, KeyPair aikMl) {
        return buildBundle(deviceId, aikEd, aikMl, false);
    }

    private static Bundle buildBundle(
            int deviceId, KeyPair aikEd, KeyPair aikMl, boolean validKemSig) {
        final KeyPair dikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        final KeyPair dikX = X3dhpqCrypto.x25519GenerateKeypair();
        final KeyPair dikMl = X3dhpqCrypto.mldsa65GenerateKeypair();
        final byte[] dcBytes = signedDc(deviceId, aikEd, aikMl, dikEd, dikX, dikMl);

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

        final Ik ikEl = new Ik();
        ikEl.setContent(dikX.pub);
        bundle.addExtension(ikEl);

        // SPK: DIK Ed25519 signature over the SPK public key.
        final KeyPair spk = X3dhpqCrypto.x25519GenerateKeypair();
        final Spk spkEl = new Spk();
        spkEl.setId(1);
        final SpkKey spkKeyEl = new SpkKey();
        spkKeyEl.setContent(spk.pub);
        spkEl.addExtension(spkKeyEl);
        final SpkSig spkSigEl = new SpkSig();
        spkSigEl.setContent(X3dhpqCrypto.ed25519Sign(dikEd.priv, spk.pub));
        spkEl.addExtension(spkSigEl);
        bundle.addExtension(spkEl);

        // KEM pre-key: hybrid DIK signature over the KEM public key.
        final Kemkeys kemkeys = new Kemkeys();
        final KemKeyPair kem = X3dhpqCrypto.mlkem768GenerateKeypair();
        final Kemkey kemkey = new Kemkey();
        kemkey.setId(1);
        final SpkKey kemKeyEl = new SpkKey();
        kemKeyEl.setContent(kem.pub);
        kemkey.addExtension(kemKeyEl);
        final SpkSig kemSigEd = new SpkSig();
        final byte[] kemEdSigner =
                validKemSig ? dikEd.priv : X3dhpqCrypto.ed25519GenerateKeypair().priv;
        kemSigEd.setContent(X3dhpqCrypto.ed25519Sign(kemEdSigner, kem.pub));
        kemkey.addExtension(kemSigEd);
        final KemMldsaSig kemSigMl = new KemMldsaSig();
        kemSigMl.setContent(X3dhpqCrypto.mldsa65Sign(dikMl.priv, kem.pub));
        kemkey.addExtension(kemSigMl);
        kemkeys.addKemkey(kemkey);
        bundle.addExtension(kemkeys);

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
