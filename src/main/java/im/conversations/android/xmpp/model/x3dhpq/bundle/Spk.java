package im.conversations.android.xmpp.model.x3dhpq.bundle;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Signed pre-key container; holds id attribute plus nested key and sig elements.
@XmlElement(name = "spk")
public class Spk extends Extension {

    public Spk() {
        super(Spk.class);
    }

    public Integer getId() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("id")));
    }

    public void setId(final int id) {
        this.setAttribute("id", id);
    }

    public SpkKey getKey() {
        return this.getExtension(SpkKey.class);
    }

    public SpkSig getSig() {
        return this.getExtension(SpkSig.class);
    }
}
