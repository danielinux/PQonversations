package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Marshalled MessageHeader (binary, base64-encoded).
@XmlElement(name = "hdr")
public class Hdr extends Extension implements ByteContent {

    public Hdr() {
        super(Hdr.class);
    }
}
