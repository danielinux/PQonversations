// SPDX-License-Identifier: AGPL-3.0-or-later
package im.conversations.x3dhpq.types;

import java.util.ArrayList;
import java.util.List;

// A group participant: their account identity public key + all their device IDs.
public final class GroupMember {

    /** WS2: per-member role in the multi-admin membership DAG. */
    public enum Role {
        MEMBER,
        ADMIN,
        OWNER
    }

    public final AccountIdentityPub aik;
    public final List<Integer> deviceIds;
    // WS2: role folded from the membership DAG (owner/admin authoring rights).
    // Defaults to MEMBER for the legacy v1 single-owner path and for callers
    // that construct members without role information.
    public final Role role;

    public GroupMember(AccountIdentityPub aik, List<Integer> deviceIds) {
        this(aik, deviceIds, Role.MEMBER);
    }

    public GroupMember(AccountIdentityPub aik, List<Integer> deviceIds, Role role) {
        this.aik       = aik;
        this.deviceIds = new ArrayList<>(deviceIds);
        this.role      = role == null ? Role.MEMBER : role;
    }

    public boolean isAdminOrOwner() {
        return role == Role.ADMIN || role == Role.OWNER;
    }
}
