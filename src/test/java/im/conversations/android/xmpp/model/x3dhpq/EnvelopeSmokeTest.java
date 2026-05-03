// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Emk;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Envelope;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Hdr;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Key;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Payload;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Prekey;
import im.conversations.android.xmpp.model.x3dhpq.envelope.PrekeyAikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.envelope.PrekeyAikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.envelope.PrekeyDc;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class EnvelopeSmokeTest {

    @Test
    public void serializeEnvelope() throws IOException {
        // Build a full envelope with one key block (including prekey) and a payload.
        final Envelope envelope = new Envelope();
        envelope.setSenderDevice(1);
        envelope.setSenderJid("alice@example.org");
        envelope.setTs("2024-01-01T00:00:00Z");

        final Key key = new Key();
        key.setRecipientDeviceId(99);

        final Hdr hdr = new Hdr();
        hdr.setContent(new byte[]{0x01, 0x02});
        key.addExtension(hdr);

        final Emk emk = new Emk();
        emk.setContent(new byte[]{0x03, 0x04});
        key.addExtension(emk);

        final Prekey prekey = new Prekey();
        prekey.setEk("AAEC");
        prekey.setOpkId(5);
        prekey.setKemkeyId(6);
        prekey.setKemCt("BAAD");

        final PrekeyDc dc = new PrekeyDc();
        dc.setContent(new byte[]{0x05});
        prekey.addExtension(dc);

        final PrekeyAikEd25519 aikEd = new PrekeyAikEd25519();
        aikEd.setContent(new byte[]{0x06});
        prekey.addExtension(aikEd);

        final PrekeyAikMldsa aikMl = new PrekeyAikMldsa();
        aikMl.setContent(new byte[]{0x07});
        prekey.addExtension(aikMl);

        key.addExtension(prekey);
        envelope.addKey(key);

        final Payload payload = new Payload();
        payload.setContent(new byte[]{0x08, 0x09});
        envelope.setPayload(payload);

        final String xml = StreamElementWriter.asString(envelope);

        Assert.assertTrue(xml.contains("x3dhpq"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:envelope:0"));
        Assert.assertTrue(xml.contains("sender-device=\"1\""));
        Assert.assertTrue(xml.contains("sender-jid=\"alice@example.org\""));
        Assert.assertTrue(xml.contains("rid=\"99\""));
        Assert.assertTrue(xml.contains("hdr"));
        Assert.assertTrue(xml.contains("emk"));
        Assert.assertTrue(xml.contains("prekey"));
        Assert.assertTrue(xml.contains("ek=\"AAEC\""));
        Assert.assertTrue(xml.contains("opk-id=\"5\""));
        Assert.assertTrue(xml.contains("kemkey-id=\"6\""));
        Assert.assertTrue(xml.contains("payload"));
        Assert.assertEquals(1, envelope.getKeys().size());
        Assert.assertEquals(
                Integer.valueOf(99),
                envelope.getKeys().iterator().next().getRecipientDeviceId());
    }
}
