// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.pair.Pair;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class PairSmokeTest {

    @Test
    public void serializePair() throws IOException {
        // Verify a pairing message element serialises with step, sid, and binary payload.
        final Pair pair = new Pair();
        pair.setStep(1);
        pair.setSid("session-abc");
        pair.setContent(new byte[]{0x01, 0x02, 0x03});

        Assert.assertEquals(Integer.valueOf(1), pair.getStep());
        Assert.assertEquals("session-abc", pair.getSid());

        final String xml = StreamElementWriter.asString(pair);

        Assert.assertTrue(xml.contains("pair"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:pair:0"));
        Assert.assertTrue(xml.contains("step=\"1\""));
        Assert.assertTrue(xml.contains("sid=\"session-abc\""));
        // base64 of {0x01, 0x02, 0x03} is AQID
        Assert.assertTrue(xml.contains("AQID"));
    }
}
