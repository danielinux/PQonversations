package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Encrypted message key (transport-key ciphertext, base64-encoded).
@XmlElement(name = "emk")
public class Emk extends Extension implements ByteContent {

    public Emk() {
        super(Emk.class);
    }
}
