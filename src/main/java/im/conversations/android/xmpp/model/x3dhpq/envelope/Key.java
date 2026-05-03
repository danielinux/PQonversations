package im.conversations.android.xmpp.model.x3dhpq.envelope;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Per-recipient key block; rid is the recipient's device id.
@XmlElement(name = "key")
public class Key extends Extension {

    public Key() {
        super(Key.class);
    }

    public Integer getRecipientDeviceId() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("rid")));
    }

    public void setRecipientDeviceId(final int rid) {
        this.setAttribute("rid", rid);
    }

    public Hdr getHdr() {
        return this.getExtension(Hdr.class);
    }

    public Emk getEmk() {
        return this.getExtension(Emk.class);
    }

    public Prekey getPrekey() {
        return this.getExtension(Prekey.class);
    }
}
