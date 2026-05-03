// SPDX-License-Identifier: AGPL-3.0-or-later
// BouncyCastle-backed HkdfSha512 for JUnit tests.
// Uses SHA-512 to match the Go reference (wolfcrypt WC_SHA512 for HKDFExtract/HKDFExpand).
package im.conversations.x3dhpq.types;

import im.conversations.x3dhpq.types.HkdfSha512;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

class BcHkdfSha512 implements HkdfSha512 {

    @Override
    public byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length) {
        HKDFBytesGenerator hk = new HKDFBytesGenerator(new SHA512Digest());
        hk.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[length];
        hk.generateBytes(out, 0, length);
        return out;
    }
}
