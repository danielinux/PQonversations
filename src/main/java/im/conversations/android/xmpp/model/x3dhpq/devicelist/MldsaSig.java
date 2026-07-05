package im.conversations.android.xmpp.model.x3dhpq.devicelist;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// ML-DSA-65 AIK signature over the devicelist SignedPart (§8.3/§8.4). Published
// as a sibling of <devicelist> inside the PEP <item>. base64-encoded 3309 bytes.
// Element name is exactly "mldsa-sig".
@XmlElement(name = "mldsa-sig")
public class MldsaSig extends Extension implements ByteContent {

    public MldsaSig() {
        super(MldsaSig.class);
    }
}
