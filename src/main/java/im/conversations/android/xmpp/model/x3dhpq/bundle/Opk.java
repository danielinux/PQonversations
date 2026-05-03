package im.conversations.android.xmpp.model.x3dhpq.bundle;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Single X25519 one-time pre-key; id attribute + base64 public-key text content.
@XmlElement(name = "opk")
public class Opk extends Extension implements ByteContent {

    public Opk() {
        super(Opk.class);
    }

    public Integer getId() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("id")));
    }

    public void setId(final int id) {
        this.setAttribute("id", id);
    }
}
