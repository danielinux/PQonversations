// SPDX-License-Identifier: AGPL-3.0-or-later
// BouncyCastle-backed Sha512 for JUnit tests.
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.types.Sha512;
import java.security.MessageDigest;

class BcSha512 implements Sha512 {

    @Override
    public byte[] hash(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            return md.digest(input);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
