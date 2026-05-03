// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

// Typed pairing-code: 9 decimal digits + 1 Luhn check digit, formatted "DDD-DDD-DDD-C".
// Port of pairing_code.go (GeneratePairingCode / FormatPairingCode / ParsePairingCode / LuhnCheck).
public final class PairingCode {

    private PairingCode() {}

    public static final int DIGITS_PER_GROUP = 3;
    public static final int NUM_GROUPS       = 3;

    // Formats a 10-character raw code (9 digits + check) as "DDD-DDD-DDD-C".
    // Returns the raw string unchanged if it is not exactly 10 characters (mirrors Go FormatPairingCode).
    public static String format(String rawCode) {
        if (rawCode == null || rawCode.length() != 10) return rawCode;
        return rawCode.substring(0, 3) + "-"
             + rawCode.substring(3, 6) + "-"
             + rawCode.substring(6, 9) + "-"
             + rawCode.substring(9, 10);
    }

    // Parses a pairing code in any of the formats:
    //   "DDD-DDD-DDD-C", "DDDDDDDDDC", "DDD DDD DDD C"
    // Strips dashes and spaces, validates 10 digits, verifies Luhn check digit.
    // Returns the stripped 10-digit string on success.
    public static String parse(String input) {
        if (input == null) throw new IllegalArgumentException("pairing: malformed code");
        // strip dashes and spaces only (mirrors Go strings.Map)
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '-' || c == ' ') continue;
            sb.append(c);
        }
        String stripped = sb.toString();
        if (stripped.length() != 10) throw new IllegalArgumentException("pairing: malformed code");
        for (int i = 0; i < 10; i++) {
            char c = stripped.charAt(i);
            if (c < '0' || c > '9') throw new IllegalArgumentException("pairing: malformed code");
        }
        char expected = luhnCheckChar(stripped.substring(0, 9));
        if (stripped.charAt(9) != expected) throw new IllegalArgumentException("pairing: check digit mismatch");
        return stripped;
    }

    // Computes the Luhn check digit for a 9-digit string.
    // Port of Go LuhnCheck: even-indexed (0-based) digits are doubled; if result > 9 subtract 9.
    // check = (10 - sum%10) % 10
    public static char luhnCheckChar(String nineDigits) {
        if (nineDigits == null || nineDigits.length() != 9) {
            throw new IllegalArgumentException("pairing: malformed code");
        }
        int sum = 0;
        for (int i = 0; i < 9; i++) {
            char c = nineDigits.charAt(i);
            if (c < '0' || c > '9') throw new IllegalArgumentException("pairing: malformed code");
            int d = c - '0';
            if (i % 2 == 0) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
        }
        int check = (10 - sum % 10) % 10;
        return (char) ('0' + check);
    }
}
