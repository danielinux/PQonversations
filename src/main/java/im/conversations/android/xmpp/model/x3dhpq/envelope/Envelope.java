package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;
import java.util.Collection;

// Root element of an x3dhpq-encrypted message stanza (element name "x3dhpq").
@XmlElement(name = "x3dhpq")
public class Envelope extends Extension {

    public Envelope() {
        super(Envelope.class);
    }

    // sender-device is the numeric device id of the originating device.
    public String getSenderDevice() {
        return this.getAttribute("sender-device");
    }

    public void setSenderDevice(final int senderDevice) {
        this.setAttribute("sender-device", senderDevice);
    }

    public String getSenderJid() {
        return this.getAttribute("sender-jid");
    }

    public void setSenderJid(final String senderJid) {
        this.setAttribute("sender-jid", senderJid);
    }

    // ts is an ISO-8601 timestamp string.
    public String getTs() {
        return this.getAttribute("ts");
    }

    public void setTs(final String ts) {
        this.setAttribute("ts", ts);
    }

    public Collection<Key> getKeys() {
        return this.getExtensions(Key.class);
    }

    public void addKey(final Key key) {
        this.addExtension(key);
    }

    public Payload getPayload() {
        return this.getExtension(Payload.class);
    }

    public void setPayload(final Payload payload) {
        this.setExtension(payload);
    }
}
