// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

// Pluggable HMAC-SHA-256 interface. Production callers inject BouncyCastle/wolfJCE.
public interface HmacSha256 {
    byte[] mac(byte[] key, byte[] message);
}
