// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PairingCodeTest {

    // KAT vectors from TestLuhnVectors in pairing_test.go.
    @Test
    void testLuhnVectors() {
        assertEquals('7', PairingCode.luhnCheckChar("123456789"));
        assertEquals('0', PairingCode.luhnCheckChar("000000000"));
        assertEquals('9', PairingCode.luhnCheckChar("999999999"));
    }

    @Test
    void testFormatProducesCorrectPattern() {
        // "1234567897" → "123-456-789-7"
        assertEquals("123-456-789-7", PairingCode.format("1234567897"));
    }

    @Test
    void testFormatLeavesWrongLengthUnchanged() {
        assertEquals("12345", PairingCode.format("12345"));
        assertNull(PairingCode.format(null));
    }

    @Test
    void testParseStripsHyphens() {
        // "123-456-789-7" → "1234567897"
        String stripped = PairingCode.parse("123-456-789-7");
        assertEquals("1234567897", stripped);
    }

    @Test
    void testParseStripsSpaces() {
        String stripped = PairingCode.parse("123 456 789 7");
        assertEquals("1234567897", stripped);
    }

    @Test
    void testParseRawCode() {
        assertEquals("1234567897", PairingCode.parse("1234567897"));
    }

    @Test
    void testRoundTrip() {
        // Build a valid raw code and round-trip it through format then parse.
        String raw = "123456789" + PairingCode.luhnCheckChar("123456789");
        assertEquals(10, raw.length());
        String formatted = PairingCode.format(raw);
        assertEquals(raw, PairingCode.parse(formatted));
    }

    @Test
    void testRoundTripAllZeros() {
        String raw = "000000000" + PairingCode.luhnCheckChar("000000000");
        assertEquals(raw, PairingCode.parse(PairingCode.format(raw)));
    }

    @Test
    void testRoundTripAllNines() {
        String raw = "999999999" + PairingCode.luhnCheckChar("999999999");
        assertEquals(raw, PairingCode.parse(PairingCode.format(raw)));
    }

    @Test
    void testBadChecksumRejected() {
        // Alter the check digit of a valid code.
        char goodCheck = PairingCode.luhnCheckChar("123456789");
        char badCheck  = (goodCheck == '9') ? '0' : (char)(goodCheck + 1);
        String bad = "123456789" + badCheck;
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> PairingCode.parse(bad));
        assertTrue(ex.getMessage().contains("check digit"),
                "Exception message must mention check digit");
    }

    @Test
    void testNonDigitRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> PairingCode.parse("12345678a7"));
    }

    @Test
    void testWrongLengthRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> PairingCode.parse("12345"));
        assertThrows(IllegalArgumentException.class,
                () -> PairingCode.parse("12345678901"));  // 11 chars
    }

    @Test
    void testNullRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> PairingCode.parse(null));
    }

    @Test
    void testLuhnCheckCharBadInputRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> PairingCode.luhnCheckChar("12345678"));  // 8 digits
        assertThrows(IllegalArgumentException.class,
                () -> PairingCode.luhnCheckChar("12345678a")); // non-digit
        assertThrows(IllegalArgumentException.class,
                () -> PairingCode.luhnCheckChar(null));
    }

    @Test
    void testConstants() {
        assertEquals(3, PairingCode.DIGITS_PER_GROUP);
        assertEquals(3, PairingCode.NUM_GROUPS);
    }
}
