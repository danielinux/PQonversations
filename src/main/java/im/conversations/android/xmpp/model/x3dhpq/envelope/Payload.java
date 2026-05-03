package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// AES-256-GCM ciphertext of the message body (base64-encoded).
@XmlElement(name = "payload")
public class Payload extends Extension implements ByteContent {

    public Payload() {
        super(Payload.class);
    }
}
