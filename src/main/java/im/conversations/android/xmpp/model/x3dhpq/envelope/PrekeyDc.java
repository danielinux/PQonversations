package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Device certificate nested inside a prekey block; base64 binary content (wire name "dc").
@XmlElement(name = "dc")
public class PrekeyDc extends Extension implements ByteContent {

    public PrekeyDc() {
        super(PrekeyDc.class);
    }
}
