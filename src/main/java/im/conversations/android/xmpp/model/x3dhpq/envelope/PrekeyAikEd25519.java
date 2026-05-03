package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Sender AIK-Ed25519 carried inline in a prekey block (wire name "aik-ed25519").
@XmlElement(name = "aik-ed25519")
public class PrekeyAikEd25519 extends Extension implements ByteContent {

    public PrekeyAikEd25519() {
        super(PrekeyAikEd25519.class);
    }
}
