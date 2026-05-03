package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Account identity key (Ed25519 half); base64 text content.
@XmlElement(name = "aik-ed25519")
public class AikEd25519 extends Extension implements ByteContent {

    public AikEd25519() {
        super(AikEd25519.class);
    }
}
