// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.ArrayList;
import java.util.List;

// A group participant: their account identity public key + all their device IDs.
public final class GroupMember {

    public final AccountIdentityPub aik;
    public final List<Integer> deviceIds;

    public GroupMember(AccountIdentityPub aik, List<Integer> deviceIds) {
        this.aik       = aik;
        this.deviceIds = new ArrayList<>(deviceIds);
    }
}
