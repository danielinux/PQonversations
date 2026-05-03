package im.conversations.android.xmpp.model.x3dhpq.recovery;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Recovery blob element; text content is the printable RecoveryBlob.format() string.
@XmlElement(name = "recovery")
public class Recovery extends Extension {

    public Recovery() {
        super(Recovery.class);
    }

    public String getRecoveryBlob() {
        return this.getContent();
    }

    public void setRecoveryBlob(final String blob) {
        this.setContent(blob);
    }
}
