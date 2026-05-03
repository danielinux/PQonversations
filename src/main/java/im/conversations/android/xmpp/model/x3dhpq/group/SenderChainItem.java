package im.conversations.android.xmpp.model.x3dhpq.group;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Sender ratchet chain item distributed to group members; base64-encoded binary payload.
@XmlElement(name = "sender-chain")
public class SenderChainItem extends Extension implements ByteContent {

    public SenderChainItem() {
        super(SenderChainItem.class);
    }
}
