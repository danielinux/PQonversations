// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

import im.conversations.x3dhpq.crypto.KeyPair;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityKey;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.DeviceCertificate;
import im.conversations.x3dhpq.types.DeviceIdentityKey;
import im.conversations.x3dhpq.types.PairingMsg;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

class PairingFsmRoundTripTest {

    private static final String CODE = "1234567890";

    private static AccountIdentityKey aik;
    private static DeviceIdentityKey dik;
    private static byte[] sid;

    @BeforeAll
    static void setUp() {
        // AIK key material.
        KeyPair aikEd    = X3dhpqCrypto.ed25519GenerateKeypair();
        KeyPair aikMldsa = X3dhpqCrypto.mldsa65GenerateKeypair();
        AccountIdentityPub aikPub = new AccountIdentityPub(aikEd.pub, aikMldsa.pub);
        aik = new AccountIdentityKey(aikEd.priv, aikMldsa.priv, aikPub);

        // DIK key material.
        KeyPair dikEd    = X3dhpqCrypto.ed25519GenerateKeypair();
        KeyPair dikX     = X3dhpqCrypto.x25519GenerateKeypair();
        KeyPair dikMldsa = X3dhpqCrypto.mldsa65GenerateKeypair();
        dik = new DeviceIdentityKey(
                dikEd.priv,  dikEd.pub,
                dikX.priv,   dikX.pub,
                dikMldsa.priv, dikMldsa.pub);

        sid = new byte[32];
        new SecureRandom().nextBytes(sid);
    }

    private static PairingFsm.Options makeOpts(boolean sharePrimary) {
        return new PairingFsm.Options(42L, sharePrimary, new byte[0], (byte) 0);
    }

    @Test
    void fullRoundTrip() throws Exception {
        PairingFsm.Existing E = new PairingFsm.Existing(aik, CODE, sid, makeOpts(false));
        PairingFsm.New      N = new PairingFsm.New(dik, CODE, sid);

        PairingMsg m1 = E.step(null);                   // PAKE1
        Assertions.assertNotNull(m1);
        Assertions.assertEquals(PairingMsg.TYPE_PAKE1, m1.getType());

        PairingMsg m2 = N.step(m1);                     // PAKE2
        Assertions.assertNotNull(m2);
        Assertions.assertEquals(PairingMsg.TYPE_PAKE2, m2.getType());

        PairingMsg m3 = E.step(m2);                     // ConfirmE
        Assertions.assertNotNull(m3);
        Assertions.assertEquals(PairingMsg.TYPE_CONFIRM, m3.getType());

        PairingMsg m4 = N.step(m3);                     // ConfirmN
        Assertions.assertNotNull(m4);
        Assertions.assertEquals(PairingMsg.TYPE_CONFIRM, m4.getType());

        PairingMsg m5 = E.step(m4);
        Assertions.assertNull(m5);                      // E waits (WAIT_DIK)

        PairingMsg m6 = N.step(null);                   // DIK pub payload
        Assertions.assertNotNull(m6);
        Assertions.assertEquals(PairingMsg.TYPE_PAYLOAD, m6.getType());

        PairingMsg m7 = E.step(m6);                     // issuance payload
        Assertions.assertNotNull(m7);
        Assertions.assertEquals(PairingMsg.TYPE_PAYLOAD, m7.getType());

        PairingMsg m8 = N.step(m7);                     // Ack
        Assertions.assertNotNull(m8);
        Assertions.assertEquals(PairingMsg.TYPE_ACK, m8.getType());

        PairingMsg m9 = E.step(m8);
        Assertions.assertNull(m9);                      // E.isDone()

        Assertions.assertTrue(E.isDone());
        Assertions.assertTrue(N.isDone());

        DeviceCertificate eCert = E.getIssuedCert();
        PairingFsm.Result nResult = N.getResult();

        Assertions.assertArrayEquals(eCert.marshal(), nResult.cert.marshal(),
                "issued cert must round-trip");
        Assertions.assertArrayEquals(aik.getPublic().marshal(), nResult.aikPub.marshal(),
                "AIK pub must round-trip");
        Assertions.assertNull(nResult.aikPriv,
                "aikPriv must be null when sharePrimary=false");
    }

    @Test
    void wrongCodeFails() throws Exception {
        PairingFsm.Existing E = new PairingFsm.Existing(aik, CODE, sid, makeOpts(false));
        PairingFsm.New      N = new PairingFsm.New(dik, "9999999999", sid);

        PairingMsg m1 = E.step(null);
        PairingMsg m2 = N.step(m1);
        PairingMsg m3 = E.step(m2);

        // N receives E's confirm with a different session key — verifyConfirm must reject it.
        Assertions.assertThrows(PairingFsm.PairingException.class, () -> N.step(m3),
                "wrong code must fail at confirm verification");
    }

    @Test
    void sharePrimaryTrue_aikPrivRoundTrips() throws Exception {
        PairingFsm.Existing E = new PairingFsm.Existing(aik, CODE, sid, makeOpts(true));
        PairingFsm.New      N = new PairingFsm.New(dik, CODE, sid);

        PairingMsg m1 = E.step(null);
        PairingMsg m2 = N.step(m1);
        PairingMsg m3 = E.step(m2);
        PairingMsg m4 = N.step(m3);
        E.step(m4);                         // → null, WAIT_DIK
        PairingMsg m6 = N.step(null);
        PairingMsg m7 = E.step(m6);
        PairingMsg m8 = N.step(m7);
        E.step(m8);

        PairingFsm.Result nResult = N.getResult();
        Assertions.assertNotNull(nResult.aikPriv, "aikPriv must be non-null when sharePrimary=true");

        // Ed25519 priv and ML-DSA-65 priv must match the original.
        Assertions.assertArrayEquals(aik.getPrivEd25519(), nResult.aikPriv.getPrivEd25519(),
                "ed25519 priv must round-trip");
        Assertions.assertArrayEquals(aik.getPrivMLDSA(), nResult.aikPriv.getPrivMLDSA(),
                "mldsa priv must round-trip");

        // The cert must carry FLAG_PRIMARY.
        Assertions.assertNotEquals(0, nResult.cert.getFlags() & PairingFsm.FLAG_PRIMARY,
                "cert flags must include FLAG_PRIMARY");
    }

    @Test
    void replayRejected() throws Exception {
        PairingFsm.Existing E = new PairingFsm.Existing(aik, CODE, sid, makeOpts(false));
        PairingFsm.New      N = new PairingFsm.New(dik, CODE, sid);

        PairingMsg m1 = E.step(null);
        PairingMsg m2 = N.step(m1);
        PairingMsg m3 = E.step(m2);
        PairingMsg m4 = N.step(m3);
        E.step(m4);                         // → null, now in WAIT_DIK

        // Replaying m4 (a CONFIRM) when E is in WAIT_DIK expects a PAYLOAD → protocol error.
        Assertions.assertThrows(PairingFsm.PairingException.class, () -> E.step(m4),
                "replaying wrong message type must throw PairingException");
    }
}
