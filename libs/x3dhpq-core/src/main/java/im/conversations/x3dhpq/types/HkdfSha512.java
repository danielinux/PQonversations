// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

// Pluggable HKDF-SHA-512 interface. Production callers inject BouncyCastle/wolfJCE.
// The Go reference (wolfcrypt) uses WC_SHA512 for both HKDFExtract and HKDFExpand;
// this interface mirrors that choice so kemCheckpointMix vectors match byte-identically.
public interface HkdfSha512 {
    // Perform HKDF-Extract(salt, ikm) then HKDF-Expand(prk, info, length).
    byte[] derive(byte[] salt, byte[] ikm, byte[] info, int length);
}
