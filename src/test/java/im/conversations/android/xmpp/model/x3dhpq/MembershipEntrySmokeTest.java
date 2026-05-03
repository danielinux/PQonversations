// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.group.MembershipEntry;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class MembershipEntrySmokeTest {

    @Test
    public void serializeMembershipEntry() throws IOException {
        // Verify the membership-entry element serialises to the group:0 namespace.
        final MembershipEntry entry = new MembershipEntry();
        entry.setContent(new byte[]{0x0A, 0x0B, 0x0C});

        final String xml = StreamElementWriter.asString(entry);

        Assert.assertTrue(xml.contains("membership-entry"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:group:0"));
        // base64 of {0x0A, 0x0B, 0x0C} is CgsM
        Assert.assertTrue(xml.contains("CgsM"));
    }
}
