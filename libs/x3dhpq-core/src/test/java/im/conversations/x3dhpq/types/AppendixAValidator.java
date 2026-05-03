/**
 * Standalone Appendix-A validator.  No JUnit dependency — run with:
 *
 *   javac -d /tmp/x3dhpq-build \
 *     ~/src/Conversations/libs/x3dhpq-core/src/main/java/im/conversations/x3dhpq/types/*.java \
 *     ~/src/Conversations/libs/x3dhpq-core/src/test/java/im/conversations/x3dhpq/types/InlineBlake2b160.java \
 *     ~/src/Conversations/libs/x3dhpq-core/src/test/java/im/conversations/x3dhpq/types/InlineSha256.java \
 *     ~/src/Conversations/libs/x3dhpq-core/src/test/java/im/conversations/x3dhpq/types/AppendixAValidator.java
 *
 *   java -cp /tmp/x3dhpq-build im.conversations.x3dhpq.types.AppendixAValidator
 *
 * Expected output:
 *   A.1 PASS
 *   A.2 PASS
 *   A.3 PASS
 *   A.4 PASS
 *
 * A.5 requires BouncyCastle (HKDF-SHA-512) and is validated via Gradle JUnit only.
 */
package im.conversations.x3dhpq.types;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AppendixAValidator {

    public static void main(String[] args) {
        boolean a1 = validateA1();
        boolean a2 = validateA2();
        boolean a3 = validateA3();
        boolean a4 = validateA4();
        System.out.println("A.1 " + (a1 ? "PASS" : "FAIL"));
        System.out.println("A.2 " + (a2 ? "PASS" : "FAIL"));
        System.out.println("A.3 " + (a3 ? "PASS" : "FAIL"));
        System.out.println("A.4 " + (a4 ? "PASS" : "FAIL"));
        if (!a1 || !a2 || !a3 || !a4) System.exit(1);
    }

    // Inline HmacSha256 using javax.crypto (always available, no BC needed).
    private static final HmacSha256 HMAC_SHA256 = (key, message) -> {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    };

    // A.1 — AIK fingerprint: PubEd25519=0x01..0x20, PubMLDSA=0xA5 x 1952.
    // Expected fingerprint: "7AD37 1A1A3 67A62 B6533 1BC5A 2204C"
    private static boolean validateA1() {
        // Sanity-check the inline BLAKE2b-160 against a known empty-string vector first.
        byte[] emptyDigest = InlineBlake2b160.blake2b160(new byte[0]);
        String emptyHex = bytesToHex(emptyDigest);
        if (!emptyHex.equals("3345524abf6bbe1809449224b5972c41790b6cf2")) {
            System.err.println("A.1 BLAKE2b-160 self-check failed: got " + emptyHex);
            return false;
        }

        byte[] pubEd = new byte[32];
        for (int i = 0; i < 32; i++) pubEd[i] = (byte) (0x01 + i);
        byte[] pubMLDSA = new byte[1952];
        Arrays.fill(pubMLDSA, (byte) 0xA5);

        AccountIdentityPub aip = new AccountIdentityPub(pubEd, pubMLDSA);
        InlineBlake2b160 hasher = new InlineBlake2b160();
        String fp = aip.fingerprint(hasher);
        String want = "7AD37 1A1A3 67A62 B6533 1BC5A 2204C";
        if (!fp.equals(want)) {
            System.err.println("A.1 fingerprint mismatch: got  \"" + fp + "\"");
            System.err.println("                           want \"" + want + "\"");
            return false;
        }
        return true;
    }

    // A.2 — DeviceCertificate.signedPart() byte-exact check.
    private static boolean validateA2() {
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

        String got = bytesToHex(dc.signedPart());
        String want =
                "0001" + "deadbeef" +
                "0020" + "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" +
                "0020" + "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40" +
                "0000" +
                "000000006630f000" +
                "01";
        if (!got.equals(want)) {
            System.err.println("A.2 signedPart mismatch:");
            System.err.println("  got  " + got);
            System.err.println("  want " + want);
            return false;
        }
        return true;
    }

    // A.3 — Sender chain step: CK = 0xAA x32.
    // MK = HMAC-SHA-256(CK, 0x01), nextCK = HMAC-SHA-256(CK, 0x02).
    private static boolean validateA3() {
        byte[] ck = new byte[32];
        Arrays.fill(ck, (byte) 0xAA);
        SenderChain chain = new SenderChain(0, ck);
        byte[] mk = chain.step(HMAC_SHA256);
        String gotMK     = bytesToHex(mk);
        String gotNextCK = bytesToHex(chain.chainKey);
        String wantMK    = "790519613efaec118e63904e01475b9543b9a15c61070227d877418c8cca415e";
        String wantCK    = "e3593f75e832b460cfc9cdea5a65902f94d9213060090c0e00a5a74306389e2e";
        if (!gotMK.equals(wantMK)) {
            System.err.println("A.3 MK mismatch: got  " + gotMK);
            System.err.println("                 want " + wantMK);
            return false;
        }
        if (!gotNextCK.equals(wantCK)) {
            System.err.println("A.3 nextCK mismatch: got  " + gotNextCK);
            System.err.println("                     want " + wantCK);
            return false;
        }
        return true;
    }

    // A.4 — AuditEntry.signedPart() byte-exact check.
    // Seq=7, PrevHash=0x55 x32, Action=AddDevice(1),
    // Payload=0x0000012300000006DEADBEEF0001 (14 bytes), Timestamp=1714483200
    private static boolean validateA4() {
        byte[] prevHash = new byte[32];
        Arrays.fill(prevHash, (byte) 0x55);

        byte[] payload = {
            0x00, 0x00, 0x01, 0x23,
            0x00, 0x00, 0x00, 0x06,
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 0x00, 0x01
        };

        AuditEntry entry = new AuditEntry(
                7L,
                prevHash,
                AuditEntry.ACTION_ADD_DEVICE,
                payload,
                1714483200L,
                null, null);

        String got = bytesToHex(entry.signedPart());
        String want =
                "5833444850512d41756469742d763100" + // "X3DHPQ-Audit-v1\x00"
                "0000000000000007" +                 // seq = 7
                "5555555555555555555555555555555555555555555555555555555555555555" + // prevHash
                "01" +                               // action = AddDevice
                "0000000e" +                         // payload length = 14
                "0000012300000006deadbeef0001" +      // payload
                "000000006630f000";                  // timestamp

        if (!got.equals(want)) {
            System.err.println("A.4 AuditEntry.signedPart mismatch:");
            System.err.println("  got  " + got);
            System.err.println("  want " + want);
            return false;
        }
        return true;
    }

    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v & 0xff));
        return sb.toString();
    }
}
