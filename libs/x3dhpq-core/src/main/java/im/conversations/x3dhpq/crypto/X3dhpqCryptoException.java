// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.crypto;

// Wraps checked crypto exceptions so callers don't need to handle JCE exception hierarchies.
public final class X3dhpqCryptoException extends RuntimeException {

    public X3dhpqCryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public X3dhpqCryptoException(String message) {
        super(message);
    }
}
