// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

// Pluggable SHA-256 interface, mirroring Blake2b160 pattern.
// Production code injects wolfJCE; tests use InlineSha256.
public interface Sha256 {
    byte[] hash(byte[] input);
}
