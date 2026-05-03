package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Device certificate (binary DeviceCertificate, base64-encoded).
@XmlElement(name = "dc")
public class Dc extends Extension implements ByteContent {

    public Dc() {
        super(Dc.class);
    }
}
