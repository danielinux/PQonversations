// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.persistance.DatabaseBackend;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkeys;
import im.conversations.android.xmpp.model.x3dhpq.bundle.KemMldsaSig;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opks;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Spk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkKey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkSig;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Ik;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Dc;
import im.conversations.x3dhpq.crypto.KemKeyPair;
import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.protocol.BundleData;
import im.conversations.x3dhpq.protocol.PqxdhInitiator;
import im.conversations.x3dhpq.protocol.PqxdhResult;
import im.conversations.x3dhpq.protocol.PrekeyEnvelope;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

/**
 * App-side integration tests for D4 session establishment through X3dhpqService.
 * Uses Robolectric so Android XML parsing (XmlReader / ExtensionFactory) is available.
 */
@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class X3dhpqSessionTest {

    private static final String ACCOUNT_UUID = "test";
    private static final Jid PEER = Jid.of("bob@example.org");
    private static final int BOB_DEVICE_ID = 42;

    // Alice (initiator): account + device keys.
    private static KeyPair aliceAikEdPair;
    private static KeyPair aliceAikMlPair;
    private static DeviceIdentityKey aliceDik;
    private static byte[] aliceDcBytes;
    private static byte[] aliceAikPubMarshal;

    // Bob (responder): keys used to build the bundle.
    private static KeyPair bobSpk;
    private static KemKeyPair bobKemKey;
    private static KeyPair bobOpk;
    private static KeyPair bobDikX25519;

    @BeforeClass
    public static void generateKeyMaterial() {
        aliceAikEdPair = X3dhpqCrypto.ed25519GenerateKeypair();
        aliceAikMlPair = X3dhpqCrypto.mldsa65GenerateKeypair();
        AccountIdentityPub aliceAip = new AccountIdentityPub(aliceAikEdPair.pub, aliceAikMlPair.pub);
        aliceAikPubMarshal = aliceAip.marshal();

        // Alice's DIK: generate X25519 key pair; embed it in a DeviceIdentityKey.
        KeyPair aliceDikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        KeyPair aliceDikX = X3dhpqCrypto.x25519GenerateKeypair();
        KeyPair aliceDikMl = X3dhpqCrypto.mldsa65GenerateKeypair();
        aliceDik = new DeviceIdentityKey(
                aliceDikEd.priv, aliceDikEd.pub,
                aliceDikX.priv, aliceDikX.pub,
                aliceDikMl.priv, aliceDikMl.pub);

        // Sign a DC for Alice with her AIK.
        long now = System.currentTimeMillis() / 1000L;
        DeviceCertificate unsignedAliceDc = new DeviceCertificate(
                1, 1, aliceDikEd.pub, aliceDikX.pub, aliceDikMl.pub, now,
                (byte) DeviceCertificate.FLAG_PRIMARY, null, null);
        byte[] aliceDcInput = concat(DeviceCertificate.SIGNING_PREFIX, unsignedAliceDc.signedPart());
        byte[] aliceSigEd = X3dhpqCrypto.ed25519Sign(aliceAikEdPair.priv, aliceDcInput);
        byte[] aliceSigMl = X3dhpqCrypto.mldsa65Sign(aliceAikMlPair.priv, aliceDcInput);
        DeviceCertificate signedAliceDc = new DeviceCertificate(
                1, 1, aliceDikEd.pub, aliceDikX.pub, aliceDikMl.pub, now,
                (byte) DeviceCertificate.FLAG_PRIMARY, aliceSigEd, aliceSigMl);
        aliceDcBytes = signedAliceDc.marshal();

        // Bob's keys for his bundle.
        bobDikX25519 = X3dhpqCrypto.x25519GenerateKeypair();
        bobSpk = X3dhpqCrypto.x25519GenerateKeypair();
        bobKemKey = X3dhpqCrypto.mlkem768GenerateKeypair();
        bobOpk = X3dhpqCrypto.x25519GenerateKeypair();
    }

    private LocalKeyBootstrapTest.FakeDao dao;
    private X3dhpqService service;

    @Before
    public void setUp() throws Exception {
        dao = new LocalKeyBootstrapTest.FakeDao();
        service = new X3dhpqService(dao);

        // Pre-populate Alice's local device and AIK rows.
        dao.putX3dhpqAccountIdentity(ACCOUNT_UUID, new byte[32], aliceAikPubMarshal, "fp");
        dao.putX3dhpqLocalDevice(ACCOUNT_UUID, 1, aliceDik.marshal(), aliceDcBytes,
                System.currentTimeMillis() / 1000L, 1);
    }

    // ---- establishOutboundSession ----

    @Test
    public void establishOutbound_noBundleInDb_returnsEmpty() {
        Optional<PqxdhResult> result = service.establishOutboundSession(PEER, BOB_DEVICE_ID);
        Assert.assertFalse("must return empty when no bundle in DB", result.isPresent());
    }

    @Test
    public void establishOutbound_withBundle_returnsResultAndPersistsSession() throws Exception {
        // Store Bob's bundle as XML.
        final byte[] bundleXml = buildBobBundleXml(true);
        dao.putX3dhpqRemoteBundle(
                ACCOUNT_UUID, PEER.asBareJid().toString(), BOB_DEVICE_ID,
                new byte[10], bundleXml, System.currentTimeMillis() / 1000L);

        Optional<PqxdhResult> result = service.establishOutboundSession(PEER, BOB_DEVICE_ID);

        Assert.assertTrue("must return a result when bundle is in DB", result.isPresent());
        PqxdhResult r = result.get();
        Assert.assertEquals("role must be INITIATOR", PqxdhResult.Role.INITIATOR, r.getRole());
        Assert.assertEquals("rootKey must be 32 bytes", 32, r.getRootKey().length);
        Assert.assertEquals("initialChainKey must be 32 bytes", 32, r.getInitialChainKey().length);
        Assert.assertEquals("AD must be 64 bytes", 64, r.getAd().length);
        Assert.assertNotNull("envelope must be present", r.getEnvelope());

        // Session blob must have been written to DB.
        DatabaseBackend.X3dhpqSessionRow sessionRow = dao.loadX3dhpqSession(
                ACCOUNT_UUID, PEER.asBareJid().toString(), BOB_DEVICE_ID);
        Assert.assertNotNull("session row must be persisted", sessionRow);
        // Session.marshal() produces a variable-length blob; verify it is parseable.
        Assert.assertTrue("state_blob must be non-empty", sessionRow.stateBlob().length > 0);
        im.conversations.x3dhpq.protocol.Session restored =
                im.conversations.x3dhpq.protocol.Session.unmarshal(sessionRow.stateBlob());
        Assert.assertNotNull("blob must unmarshal back to a Session", restored);
    }

    @Test
    public void serialiseSession_roundtrip() {
        // Build a synthetic PqxdhResult; verify serialise produces a parseable Session blob.
        byte[] rk = new byte[32];
        byte[] ck = new byte[32];
        byte[] ad = new byte[64];
        Arrays.fill(rk, (byte) 0xAB);
        Arrays.fill(ck, (byte) 0xCD);
        Arrays.fill(ad, (byte) 0xEF);
        PqxdhResult result = new PqxdhResult(PqxdhResult.Role.INITIATOR, rk, ck, ad, null);
        byte[] blob = X3dhpqService.serialiseSession(result);
        // Session.marshal() produces a variable-length blob starting with version byte 0x01.
        Assert.assertTrue("blob must be non-empty", blob.length > 0);
        Assert.assertEquals("blob must start with version 0x01", 0x01, blob[0]);
        // Blob must round-trip through Session.unmarshal without throwing.
        im.conversations.x3dhpq.protocol.Session restored =
                im.conversations.x3dhpq.protocol.Session.unmarshal(blob);
        Assert.assertNotNull("unmarshal must succeed", restored);
    }

    @Test
    public void acceptInbound_consumesOpk() throws Exception {
        // Pre-populate Bob's local keys in the DAO (Bob is the service owner here).
        final LocalKeyBootstrapTest.FakeDao bobDao = new LocalKeyBootstrapTest.FakeDao();
        final X3dhpqService bobService = new X3dhpqService(bobDao);

        // Populate Bob's keys in his DAO.
        KeyPair bobAikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        KeyPair bobAikMl = X3dhpqCrypto.mldsa65GenerateKeypair();
        AccountIdentityPub bobAip = new AccountIdentityPub(bobAikEd.pub, bobAikMl.pub);
        bobDao.putX3dhpqAccountIdentity("test", new byte[32], bobAip.marshal(), "fp");

        // Bob's DIK.
        KeyPair bobDikEd = X3dhpqCrypto.ed25519GenerateKeypair();
        KeyPair bobDikX = X3dhpqCrypto.x25519GenerateKeypair();
        KeyPair bobDikMl = X3dhpqCrypto.mldsa65GenerateKeypair();
        DeviceIdentityKey bobDik = new DeviceIdentityKey(
                bobDikEd.priv, bobDikEd.pub, bobDikX.priv, bobDikX.pub, bobDikMl.priv, bobDikMl.pub);
        bobDao.putX3dhpqLocalDevice("test", BOB_DEVICE_ID, bobDik.marshal(), aliceDcBytes,
                System.currentTimeMillis() / 1000L, 1);

        // Bob's SPK.
        KeyPair spk = X3dhpqCrypto.x25519GenerateKeypair();
        bobDao.putX3dhpqSignedPreKey("test", 1, spk.pub, spk.priv, new byte[64], new byte[3309], 0L);

        // Bob's KEM pre-key. This test drives PqxdhInitiator/acceptInboundSession
        // directly (not handleInboundBundle), so KEM-sig verification isn't on the
        // path; placeholder signatures are sufficient here.
        KemKeyPair bobKem = X3dhpqCrypto.mlkem768GenerateKeypair();
        bobDao.putX3dhpqKemPreKey("test", 1, bobKem.pub, bobKem.priv, new byte[64], new byte[3309]);

        // Bob's OPK.
        KeyPair opk = X3dhpqCrypto.x25519GenerateKeypair();
        bobDao.putX3dhpqOneTimePreKey("test", 99, opk.pub, opk.priv);

        // Build a bundle matching Bob's keys.
        BundleData bobBundleData = new BundleData(
                new byte[32], new byte[1952], aliceDcBytes,
                bobDikEd.pub, bobDikX.pub, new byte[1952],
                1, spk.pub, new byte[64],
                java.util.Collections.singletonList(
                        new BundleData.KemPreKey(1, bobKem.pub)),
                java.util.Collections.singletonList(
                        new BundleData.OneTimePreKey(99, opk.pub)));

        // Alice initiates with Bob's bundle.
        PqxdhResult aliceResult = PqxdhInitiator.initiate(
                aliceDik.getPrivX25519(), aliceDik.getPubX25519(),
                aliceDik.getPubEd25519(), aliceDcBytes,
                aliceAikEdPair.pub, aliceAikMlPair.pub,
                bobBundleData,
                X3dhpqCrypto.HKDF_SHA512);

        PrekeyEnvelope env = aliceResult.getEnvelope();
        Assert.assertNotNull(env);

        // Bob accepts inbound session.
        PqxdhResult bobResult = bobService.acceptInboundSession(
                Jid.of("alice@example.org"), 1, env);

        // Keys must match (root key and chain key are symmetric from the same HKDF output).
        Assert.assertArrayEquals("root keys must match", aliceResult.getRootKey(), bobResult.getRootKey());
        Assert.assertArrayEquals("chain keys must match",
                aliceResult.getInitialChainKey(), bobResult.getInitialChainKey());

        // OPK must have been marked consumed.
        Assert.assertFalse("OPK 99 must be consumed",
                bobDao.listX3dhpqUnusedOneTimePreKeyIds("test").contains(99));

        // Session row must be persisted for Bob.
        Assert.assertNotNull("Bob's session must be persisted",
                bobDao.loadX3dhpqSession("test", "alice@example.org", 1));
    }

    // Build Bob's bundle XML with optional OPK, using pre-class-level keys.
    private static byte[] buildBobBundleXml(boolean includeOpk) throws Exception {
        Bundle bundle = new Bundle();

        AikEd25519 aikEd = new AikEd25519();
        aikEd.setContent(new byte[32]);
        bundle.addExtension(aikEd);

        AikMldsa aikMl = new AikMldsa();
        aikMl.setContent(new byte[1952]);
        bundle.addExtension(aikMl);

        Dc dc = new Dc();
        dc.setContent(new byte[10]);
        bundle.addExtension(dc);

        // ik = dikX25519Pub
        Ik ik = new Ik();
        ik.setContent(bobDikX25519.pub);
        bundle.addExtension(ik);

        Spk spk = new Spk();
        spk.setId(1);
        SpkKey spkKey = new SpkKey();
        spkKey.setContent(bobSpk.pub);
        spk.addExtension(spkKey);
        SpkSig spkSig = new SpkSig();
        spkSig.setContent(new byte[64]);
        spk.addExtension(spkSig);
        bundle.addExtension(spk);

        Kemkeys kemkeys = new Kemkeys();
        Kemkey kemkey = new Kemkey();
        kemkey.setId(1);
        SpkKey kemKeyEl = new SpkKey();
        kemKeyEl.setContent(bobKemKey.pub);
        kemkey.addExtension(kemKeyEl);
        SpkSig kemSigEl = new SpkSig();
        kemSigEl.setContent(new byte[64]);
        kemkey.addExtension(kemSigEl);
        KemMldsaSig kemMldsaEl = new KemMldsaSig();
        kemMldsaEl.setContent(new byte[3309]);
        kemkey.addExtension(kemMldsaEl);
        kemkeys.addKemkey(kemkey);
        bundle.addExtension(kemkeys);

        if (includeOpk) {
            Opks opks = new Opks();
            Opk opk = new Opk();
            opk.setId(5);
            opk.setContent(bobOpk.pub);
            opks.addOpk(opk);
            bundle.addExtension(opks);
        }

        return StreamElementWriter.asString(bundle).getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
