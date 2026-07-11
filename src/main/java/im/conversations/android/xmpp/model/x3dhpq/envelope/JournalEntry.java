package im.conversations.android.xmpp.model.x3dhpq.envelope;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// WS1: a group membership-journal entry carried as a child of an ordinary
// type='groupchat' <message> (namespace urn:xmppqr:x3dhpq:envelope:0), instead
// of a PubSub item on a room-JID node that stock MUC services do not serve to
// members. The MUC channel is a single shared, server-archived (MAM) log every
// member already reads; late joiners catch up via MUC MAM. Base64 text content
// holds the binary-marshalled AuditEntry from x3dhpq-core (bytes unchanged).
@XmlElement(name = "journal-entry")
public class JournalEntry extends Extension implements ByteContent {

    public JournalEntry() {
        super(JournalEntry.class);
    }
}
