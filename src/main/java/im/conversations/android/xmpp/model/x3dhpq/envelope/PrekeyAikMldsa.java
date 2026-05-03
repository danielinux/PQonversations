package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Sender AIK-ML-DSA carried inline in a prekey block (wire name "aik-mldsa").
@XmlElement(name = "aik-mldsa")
public class PrekeyAikMldsa extends Extension implements ByteContent {

    public PrekeyAikMldsa() {
        super(PrekeyAikMldsa.class);
    }
}
