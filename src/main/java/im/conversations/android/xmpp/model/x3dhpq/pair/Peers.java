package im.conversations.android.xmpp.model.x3dhpq.pair;

import com.google.common.base.Strings;
import com.google.common.primitives.Ints;
import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.Extension;

// Result child of the verify-device IQ. Reports the number of peer
// resources the server fanned the headline announcement out to.
@XmlElement(name = "peers")
public class Peers extends Extension {

    public Peers() {
        super(Peers.class);
    }

    public Integer getCount() {
        return Ints.tryParse(Strings.nullToEmpty(this.getAttribute("count")));
    }

    public void setCount(final int count) {
        this.setAttribute("count", count);
    }
}
