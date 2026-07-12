package im.conversations.android.xmpp.model.carbons;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// XEP-0280 §6.1: a <private/> child tells the server NOT to carbon-copy this message to the
// sender's or recipient's other resources. Pairing handshakes are strictly point-to-point.
@XmlElement
public class Private extends Extension {

    public Private() {
        super(Private.class);
    }
}
