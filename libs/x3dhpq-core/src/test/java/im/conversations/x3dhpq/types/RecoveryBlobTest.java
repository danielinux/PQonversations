// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

class RecoveryBlobTest {

    // Synthetic fixed values for deterministic tests
    private static final byte[] SALT  = new byte[16]; // all zeros
    private static final byte[] NONCE = new byte[12]; // all zeros
    private static final byte[] CT    = new byte[32]; // all zeros

    static {
        Arrays.fill(SALT, (byte) 0xAB);
        Arrays.fill(NONCE, (byte) 0xCD);
        Arrays.fill(CT, (byte) 0xEF);
    }

    @Test
    void testFormatAndParse() {
        RecoveryBlob orig = new RecoveryBlob(131072, 8, 1, SALT, NONCE, CT);
        String formatted  = orig.format();
        // Must start with correct header
        assertTrue(formatted.startsWith("x3dhpqv1$N=131072,r=8,p=1$"), "header mismatch: " + formatted);

        RecoveryBlob parsed = RecoveryBlob.parse(formatted);
        assertEquals(131072, parsed.getN());
        assertEquals(8,      parsed.getR());
        assertEquals(1,      parsed.getP());
        assertArrayEquals(SALT,  parsed.getSalt());
        assertArrayEquals(NONCE, parsed.getNonce());
        assertArrayEquals(CT,    parsed.getCiphertext());
    }

    @Test
    void testRoundTripIdempotent() {
        RecoveryBlob orig = new RecoveryBlob(131072, 8, 1, SALT, NONCE, CT);
        // format → parse → format must be stable
        assertEquals(orig.format(), RecoveryBlob.parse(orig.format()).format());
    }

    @Test
    void testParseRealishString() {
        // Build a synthetic string with known base64 values and verify round-trip
        String s = "x3dhpqv1$N=131072,r=8,p=1$q6urq6urq6urqw$zc3Nzc3Nzc3N$7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+8";
        RecoveryBlob blob = RecoveryBlob.parse(s);
        assertEquals(131072, blob.getN());
        assertEquals(8,      blob.getR());
        assertEquals(1,      blob.getP());
        // format() may differ slightly due to padding; just verify it re-parses cleanly
        RecoveryBlob reparsed = RecoveryBlob.parse(blob.format());
        assertArrayEquals(blob.getSalt(),       reparsed.getSalt());
        assertArrayEquals(blob.getNonce(),      reparsed.getNonce());
        assertArrayEquals(blob.getCiphertext(), reparsed.getCiphertext());
    }

    @Test
    void testWrongHeaderRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> RecoveryBlob.parse("x3dhpqv2$N=131072,r=8,p=1$AAAA$AAAA$AAAA"));
    }

    @Test
    void testWrongNRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> RecoveryBlob.parse("x3dhpqv1$N=65536,r=8,p=1$AAAA$AAAA$AAAA"));
    }

    @Test
    void testWrongRRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> RecoveryBlob.parse("x3dhpqv1$N=131072,r=4,p=1$AAAA$AAAA$AAAA"));
    }

    @Test
    void testWrongPRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> RecoveryBlob.parse("x3dhpqv1$N=131072,r=8,p=2$AAAA$AAAA$AAAA"));
    }

    @Test
    void testTruncatedInputRejected() {
        // only 3 '$' sections instead of 4
        assertThrows(IllegalArgumentException.class,
                () -> RecoveryBlob.parse("x3dhpqv1$N=131072,r=8,p=1$AAAA$AAAA"));
    }

    @Test
    void testEmptyStringRejected() {
        assertThrows(IllegalArgumentException.class, () -> RecoveryBlob.parse(""));
    }

    @Test
    void testNullInputRejected() {
        assertThrows(IllegalArgumentException.class, () -> RecoveryBlob.parse(null));
    }

    @Test
    void testConstructorRejectsWrongN() {
        assertThrows(IllegalArgumentException.class,
                () -> new RecoveryBlob(65536, 8, 1, SALT, NONCE, CT));
    }

    @Test
    void testConstructorRejectsEmptySalt() {
        assertThrows(IllegalArgumentException.class,
                () -> new RecoveryBlob(131072, 8, 1, new byte[0], NONCE, CT));
    }
}
