// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.group.SenderChainItem;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class SenderChainItemSmokeTest {

    @Test
    public void serializeSenderChainItem() throws IOException {
        // Verify the sender-chain element serialises to the group:0 namespace.
        final SenderChainItem item = new SenderChainItem();
        item.setContent(new byte[]{0x0D, 0x0E, 0x0F});

        final String xml = StreamElementWriter.asString(item);

        Assert.assertTrue(xml.contains("sender-chain"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:group:0"));
        // base64 of {0x0D, 0x0E, 0x0F} is DQ4P
        Assert.assertTrue(xml.contains("DQ4P"));
    }
}
