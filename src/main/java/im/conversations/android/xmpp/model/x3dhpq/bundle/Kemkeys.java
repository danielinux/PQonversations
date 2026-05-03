package im.conversations.android.xmpp.model.x3dhpq.bundle;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;
import java.util.Collection;

// Container for KEM one-time pre-keys published in the bundle.
@XmlElement(name = "kemkeys")
public class Kemkeys extends Extension {

    public Kemkeys() {
        super(Kemkeys.class);
    }

    public Collection<Kemkey> getKemkeys() {
        return this.getExtensions(Kemkey.class);
    }

    public void addKemkey(final Kemkey kemkey) {
        this.addExtension(kemkey);
    }
}
