// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.recovery.Recovery;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class RecoverySmokeTest {

    @Test
    public void serializeRecovery() throws IOException {
        // Verify the recovery element serialises with the correct namespace and text content.
        final Recovery recovery = new Recovery();
        recovery.setRecoveryBlob("word1 word2 word3");

        Assert.assertEquals("word1 word2 word3", recovery.getRecoveryBlob());

        final String xml = StreamElementWriter.asString(recovery);

        Assert.assertTrue(xml.contains("recovery"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:recovery:0"));
        Assert.assertTrue(xml.contains("word1 word2 word3"));
    }
}
