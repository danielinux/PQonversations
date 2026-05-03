package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Account identity key (ML-DSA / Dilithium half); base64 text content.
@XmlElement(name = "aik-mldsa")
public class AikMldsa extends Extension implements ByteContent {

    public AikMldsa() {
        super(AikMldsa.class);
    }
}
