package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Device identity key (Ed25519 signing half); base64 text content.
@XmlElement(name = "dik-ed25519")
public class DikEd25519 extends Extension implements ByteContent {

    public DikEd25519() {
        super(DikEd25519.class);
    }
}
