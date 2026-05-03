// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.Objects;

// Immutable key for the recvChains map: (aikFingerprint, deviceId, epoch).
public record RecvKey(String aikFp, int deviceId, int epoch) {

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof RecvKey)) return false;
        RecvKey o = (RecvKey) obj;
        return epoch == o.epoch && deviceId == o.deviceId && Objects.equals(aikFp, o.aikFp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(aikFp, deviceId, epoch);
    }
}
