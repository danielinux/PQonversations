// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

// Pluggable SHA-512 interface. Production callers inject BouncyCastle/wolfJCE.
// Used in kemCheckpointMix for transcript hashing and history accumulation.
public interface Sha512 {
    byte[] hash(byte[] input);
}
