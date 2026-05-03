// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

// Pluggable BLAKE2b-160 hasher; production callers inject BouncyCastle/wolfJCE.
public interface Blake2b160 {
    // Returns the 20-byte BLAKE2b-160 digest of input.
    byte[] hash(byte[] input);
}
