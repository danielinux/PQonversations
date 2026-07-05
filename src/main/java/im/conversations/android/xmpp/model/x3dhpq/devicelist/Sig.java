package im.conversations.android.xmpp.model.x3dhpq.devicelist;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Ed25519 AIK signature over the devicelist SignedPart (§8.3/§8.4). Published
// as a sibling of <devicelist> inside the PEP <item>. base64-encoded 64 bytes.
@XmlElement(name = "sig")
public class Sig extends Extension implements ByteContent {

    public Sig() {
        super(Sig.class);
    }
}
