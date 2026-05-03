package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Public key material of the signed pre-key; base64 text content.
@XmlElement(name = "key")
public class SpkKey extends Extension implements ByteContent {

    public SpkKey() {
        super(SpkKey.class);
    }
}
