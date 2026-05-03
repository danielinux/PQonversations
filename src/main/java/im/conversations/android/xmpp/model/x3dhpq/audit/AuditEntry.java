package im.conversations.android.xmpp.model.x3dhpq.audit;

import im.conversations.android.annotation.XmlElement;
import im.conversations.android.xmpp.model.ByteContent;
import im.conversations.android.xmpp.model.Extension;

// Opaque audit-chain entry published to the per-account audit:0 PEP node (§11 of XEP).
// Text content is a base64-encoded marshalled binary AuditEntry from x3dhpq-core.
@XmlElement(name = "audit-entry")
public class AuditEntry extends Extension implements ByteContent {

    public AuditEntry() {
        super(AuditEntry.class);
    }
}
