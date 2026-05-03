package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Device identity key (ML-DSA signing half); base64 text content.
@XmlElement(name = "dik-mldsa")
public class DikMldsa extends Extension implements ByteContent {

    public DikMldsa() {
        super(DikMldsa.class);
    }
}
