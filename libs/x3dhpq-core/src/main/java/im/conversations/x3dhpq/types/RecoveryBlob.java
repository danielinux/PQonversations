// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.Arrays;
import java.util.Base64;

/**
 * Printable string format for a sealed AIK recovery blob.
 *
 * Format (mirrors Go recovery.go parseBlob):
 *   x3dhpqv1$N=131072,r=8,p=1$<base64url-nopad-salt>$<base64url-nopad-nonce>$<base64url-nopad-ciphertext>
 *
 * The scrypt params are always N=131072, r=8, p=1 per spec §14; any other values
 * are rejected with IllegalArgumentException.
 *
 * Actual sealing/opening with scrypt + AES-GCM is Wave-A territory; this class
 * handles only the string format.
 */
public final class RecoveryBlob {

    private static final String HEADER = "x3dhpqv1";
    static final int REQUIRED_N = 131072;
    static final int REQUIRED_R = 8;
    static final int REQUIRED_P = 1;

    // Base64 decoder/encoder used by Go (RawStdEncoding = standard alphabet, no padding)
    private static final Base64.Decoder B64_DEC = Base64.getDecoder(); // handles padding too
    private static final Base64.Encoder B64_ENC = Base64.getEncoder().withoutPadding();

    final int n;
    final int r;
    final int p;
    final byte[] salt;
    final byte[] nonce;
    final byte[] ciphertext;

    public RecoveryBlob(int n, int r, int p, byte[] salt, byte[] nonce, byte[] ciphertext) {
        if (n != REQUIRED_N) throw new IllegalArgumentException("scrypt N must be " + REQUIRED_N + ", got " + n);
        if (r != REQUIRED_R) throw new IllegalArgumentException("scrypt r must be " + REQUIRED_R + ", got " + r);
        if (p != REQUIRED_P) throw new IllegalArgumentException("scrypt p must be " + REQUIRED_P + ", got " + p);
        if (salt == null || salt.length == 0)       throw new IllegalArgumentException("salt must not be empty");
        if (nonce == null || nonce.length == 0)     throw new IllegalArgumentException("nonce must not be empty");
        if (ciphertext == null || ciphertext.length == 0) throw new IllegalArgumentException("ciphertext must not be empty");
        this.n          = n;
        this.r          = r;
        this.p          = p;
        this.salt       = Arrays.copyOf(salt, salt.length);
        this.nonce      = Arrays.copyOf(nonce, nonce.length);
        this.ciphertext = Arrays.copyOf(ciphertext, ciphertext.length);
    }

    public int getN()               { return n; }
    public int getR()               { return r; }
    public int getP()               { return p; }
    public byte[] getSalt()         { return Arrays.copyOf(salt, salt.length); }
    public byte[] getNonce()        { return Arrays.copyOf(nonce, nonce.length); }
    public byte[] getCiphertext()   { return Arrays.copyOf(ciphertext, ciphertext.length); }

    /**
     * Parse a canonical recovery blob string.
     * Rejects: wrong header, wrong scrypt params, truncated/invalid base64.
     */
    public static RecoveryBlob parse(String s) {
        if (s == null) throw new IllegalArgumentException("null input");
        // SplitN with limit 5 → ["x3dhpqv1", "N=...", "<salt>", "<nonce>", "<ct>"]
        String[] parts = splitN(s, '$', 5);
        if (parts == null || parts.length != 5) {
            throw new IllegalArgumentException("RecoveryBlob: expected 4 '$' separators");
        }
        if (!HEADER.equals(parts[0])) {
            throw new IllegalArgumentException("RecoveryBlob: wrong header '" + parts[0] + "'");
        }

        int[] params = parseParams(parts[1]);

        byte[] salt, nonce, ct;
        try {
            salt  = decodeB64(parts[2]);
            nonce = decodeB64(parts[3]);
            ct    = decodeB64(parts[4]);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("RecoveryBlob: base64 decode failed: " + e.getMessage());
        }
        if (salt.length == 0)  throw new IllegalArgumentException("RecoveryBlob: empty salt");
        if (nonce.length == 0) throw new IllegalArgumentException("RecoveryBlob: empty nonce");
        if (ct.length == 0)    throw new IllegalArgumentException("RecoveryBlob: empty ciphertext");

        // constructor validates params
        return new RecoveryBlob(params[0], params[1], params[2], salt, nonce, ct);
    }

    /** Emits the canonical format string. */
    public String format() {
        return HEADER
                + "$N=" + n + ",r=" + r + ",p=" + p
                + "$" + encodeB64(salt)
                + "$" + encodeB64(nonce)
                + "$" + encodeB64(ciphertext);
    }

    // --- helpers ---

    private static int[] parseParams(String s) {
        // "N=131072,r=8,p=1"
        String[] kv = s.split(",");
        if (kv.length != 3) {
            throw new IllegalArgumentException("RecoveryBlob: malformed params '" + s + "'");
        }
        int[] result = new int[3];
        for (String pair : kv) {
            String[] eq = pair.split("=", 2);
            if (eq.length != 2) throw new IllegalArgumentException("RecoveryBlob: bad param pair '" + pair + "'");
            int val;
            try {
                val = Integer.parseInt(eq[1]);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("RecoveryBlob: non-integer param '" + pair + "'");
            }
            switch (eq[0]) {
                case "N": result[0] = val; break;
                case "r": result[1] = val; break;
                case "p": result[2] = val; break;
                default:  throw new IllegalArgumentException("RecoveryBlob: unknown param '" + eq[0] + "'");
            }
        }
        // validate values (constructor will also check, but give better error here)
        if (result[0] != REQUIRED_N) {
            throw new IllegalArgumentException("RecoveryBlob: N must be " + REQUIRED_N + ", got " + result[0]);
        }
        if (result[1] != REQUIRED_R) {
            throw new IllegalArgumentException("RecoveryBlob: r must be " + REQUIRED_R + ", got " + result[1]);
        }
        if (result[2] != REQUIRED_P) {
            throw new IllegalArgumentException("RecoveryBlob: p must be " + REQUIRED_P + ", got " + result[2]);
        }
        return result;
    }

    /** Split s on delimiter, returning at most limit parts (last part may contain delimiter). */
    private static String[] splitN(String s, char delim, int limit) {
        String[] result = new String[limit];
        int start = 0;
        int count = 0;
        for (int i = 0; i < s.length() && count < limit - 1; i++) {
            if (s.charAt(i) == delim) {
                result[count++] = s.substring(start, i);
                start = i + 1;
            }
        }
        result[count++] = s.substring(start);
        if (count < limit) {
            String[] trimmed = new String[count];
            System.arraycopy(result, 0, trimmed, 0, count);
            return trimmed;
        }
        return result;
    }

    private static byte[] decodeB64(String s) {
        // Go uses RawStdEncoding (no padding); Java's getDecoder handles both padded and unpadded
        try {
            return B64_DEC.decode(s);
        } catch (Exception e) {
            throw new IllegalArgumentException("base64 decode error: " + e.getMessage());
        }
    }

    private static String encodeB64(byte[] b) {
        // withoutPadding() matches Go's base64.RawStdEncoding
        return B64_ENC.encodeToString(b);
    }
}
