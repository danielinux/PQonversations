package im.conversations.android.xmpp.model.x3dhpq.group;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Owner-signed membership journal entry published to the room's group:0 PEP node (§13.8).
// Base64 text content holds the binary-marshalled MembershipEntry from x3dhpq-core.
@XmlElement(name = "membership-entry")
public class MembershipEntry extends Extension implements ByteContent {

    public MembershipEntry() {
        super(MembershipEntry.class);
    }
}
