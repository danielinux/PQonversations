// SPDX-License-Identifier: AGPL-3.0-or-later
// BouncyCastle-backed HmacSha256 for JUnit tests (not for standalone validator).
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.types.HmacSha256;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class BcHmacSha256 implements HmacSha256 {

    @Override
    public byte[] mac(byte[] key, byte[] message) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
