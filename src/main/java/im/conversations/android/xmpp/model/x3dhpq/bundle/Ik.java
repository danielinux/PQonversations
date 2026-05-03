package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Device identity key (X25519 DH half, dik-x25519 in dino); base64 text content.
@XmlElement(name = "ik")
public class Ik extends Extension implements ByteContent {

    public Ik() {
        super(Ik.class);
    }
}
