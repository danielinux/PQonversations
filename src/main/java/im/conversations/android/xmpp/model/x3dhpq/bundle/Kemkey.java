package im.conversations.android.xmpp.model.x3dhpq.bundle;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Single KEM pre-key; id attribute + base64 public-key text content.
@XmlElement(name = "kemkey")
public class Kemkey extends Extension implements ByteContent {

    public Kemkey() {
        super(Kemkey.class);
    }

    public Integer getId() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("id")));
    }

    public void setId(final int id) {
        this.setAttribute("id", id);
    }
}
