// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.audit.AuditEntry;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class AuditEntrySmokeTest {

    @Test
    public void serializeAuditEntry() throws IOException {
        // Verify that an audit entry serialises with the correct element name and namespace.
        final AuditEntry entry = new AuditEntry();
        entry.setContent(new byte[]{0x01, 0x02, 0x03});

        final String xml = StreamElementWriter.asString(entry);

        Assert.assertTrue(xml.contains("audit-entry"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:audit:0"));
        // base64 of {0x01, 0x02, 0x03} is AQID
        Assert.assertTrue(xml.contains("AQID"));
    }
}
