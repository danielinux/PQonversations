package im.conversations.android.xmpp.model.x3dhpq.devicelist;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Device certificate (base64-encoded DeviceCertificate binary) nested inside a Device element.
@XmlElement(name = "cert")
public class Cert extends Extension implements ByteContent {

    public Cert() {
        super(Cert.class);
    }
}
