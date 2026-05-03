// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.protocol;

// Thrown when a Triple-Ratchet operation fails (bad MAC, replay, too-many-skipped, etc.).
public final class SessionException extends Exception {

    public SessionException(String message) {
        super(message);
    }

    public SessionException(String message, Throwable cause) {
        super(message, cause);
    }
}
