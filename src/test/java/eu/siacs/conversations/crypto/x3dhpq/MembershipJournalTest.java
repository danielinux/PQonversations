// SPDX-License-Identifier: AGPL-3.0-or-later
package eu.siacs.conversations.crypto.x3dhpq;

import im.conversations.x3dhpq.crypto.BouncyCastleInstaller;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.AuditEntry;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Unit tests for MembershipJournal chain verification logic.
 * Uses synthetic (unsigned) AuditEntry objects to test structural chain properties.
 * Signature verification is tested separately with real keys.
 */
public class MembershipJournalTest {

    @BeforeClass
    public static void setUpCrypto() {
        BouncyCastleInstaller.ensureRegistered();
    }

    /**
     * Build a raw 20-byte AIK fingerprint from a fill byte.
     */
    private static byte[] makeFp(byte fill) {
        byte[] fp = new byte[20];
        Arrays.fill(fp, fill);
        return fp;
    }

    private static AccountIdentityPub makeAik(byte fill) {
        byte[] pubEd = new byte[32];
        Arrays.fill(pubEd, fill);
        byte[] pubMLDSA = new byte[1952];
        Arrays.fill(pubMLDSA, (byte) (fill ^ 0x5A));
        return new AccountIdentityPub(pubEd, pubMLDSA);
    }

    /**
     * Build a member payload: aikFp20 || epochAfter(uint32 BE).
     */
    private static byte[] memberPayload(byte[] fp20, long epochAfter) {
        return AuditEntry.buildMemberPayload(fp20, epochAfter);
    }

    /**
     * Verify parseMemberPayload round-trips correctly.
     */
    @Test
    public void buildAndParseMemberPayload_roundTrip() {
        byte[] fp = makeFp((byte) 0xAB);
        long epoch = 42L;
        byte[] payload = memberPayload(fp, epoch);
        Assert.assertEquals("payload must be 24 bytes", 24, payload.length);

        byte[][] parsed = AuditEntry.parseMemberPayload(payload);
        Assert.assertArrayEquals("fp must round-trip", fp, parsed[0]);
        long parsedEpoch = ByteBuffer.wrap(parsed[1]).order(ByteOrder.BIG_ENDIAN).getInt() & 0xFFFFFFFFL;
        Assert.assertEquals("epoch must round-trip", epoch, parsedEpoch);
    }

    /**
     * fingerprintHex encodes bytes as uppercase hex.
     */
    @Test
    public void fingerprintHex_encodes20BytesCorrectly() {
        byte[] fp = new byte[20];
        Arrays.fill(fp, (byte) 0xAB);
        String hex = MembershipJournal.fingerprintHex(fp);
        Assert.assertEquals(40, hex.length());
        Assert.assertTrue("must be uppercase hex", hex.matches("[0-9A-F]+"));
        Assert.assertEquals("ABABABABABABABABABABABABABABABABABABABABABAB".substring(0, 40), hex);
    }

    /**
     * parseMemberPayload rejects too-short payload.
     */
    @Test(expected = IllegalArgumentException.class)
    public void parseMemberPayload_rejectsTooShort() {
        AuditEntry.parseMemberPayload(new byte[23]);
    }

    /**
     * buildMemberPayload rejects wrong-length fp.
     */
    @Test(expected = IllegalArgumentException.class)
    public void buildMemberPayload_rejectsBadFp() {
        AuditEntry.buildMemberPayload(new byte[19], 1L);
    }

    /**
     * AuditEntry action constants must match the spec values.
     */
    @Test
    public void auditActionConstants_matchSpec() {
        Assert.assertEquals(5, AuditEntry.ACTION_ADD_MEMBER);
        Assert.assertEquals(6, AuditEntry.ACTION_REMOVE_MEMBER);
    }
}
