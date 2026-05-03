package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;
import java.util.Collection;

// Container for X25519 one-time pre-keys published in the bundle.
@XmlElement(name = "opks")
public class Opks extends Extension {

    public Opks() {
        super(Opks.class);
    }

    public Collection<Opk> getOpks() {
        return this.getExtensions(Opk.class);
    }

    public void addOpk(final Opk opk) {
        this.addExtension(opk);
    }
}
