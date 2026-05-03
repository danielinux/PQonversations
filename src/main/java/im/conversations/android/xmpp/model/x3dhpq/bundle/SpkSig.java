package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Ed25519 signature over the signed pre-key; base64 text content.
@XmlElement(name = "sig")
public class SpkSig extends Extension implements ByteContent {

    public SpkSig() {
        super(SpkSig.class);
    }
}
