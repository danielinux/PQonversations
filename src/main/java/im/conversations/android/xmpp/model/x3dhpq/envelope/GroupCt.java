package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// AES-256-GCM ciphertext for a group message (base64-encoded).
@XmlElement(name = "ct")
public class GroupCt extends Extension implements ByteContent {

    public GroupCt() {
        super(GroupCt.class);
    }
}
