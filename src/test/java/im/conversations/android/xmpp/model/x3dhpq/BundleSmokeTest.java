// Round-trip parse coverage is deferred: the annotation-processor-generated
// Extensions registry is only available after a full compile; these tests verify
// construction + serialisation only.
package im.conversations.android.xmpp.model.x3dhpq;

import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikEd25519;
import im.conversations.android.xmpp.model.x3dhpq.bundle.AikMldsa;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Bundle;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Dc;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Ik;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Kemkeys;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Opks;
import im.conversations.android.xmpp.model.x3dhpq.bundle.Spk;
import im.conversations.android.xmpp.model.x3dhpq.bundle.KemMldsaSig;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkKey;
import im.conversations.android.xmpp.model.x3dhpq.bundle.SpkSig;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class BundleSmokeTest {

    @Test
    public void serializeBundle() throws IOException {
        // Construct a minimal bundle and verify it serialises to the expected wire format.
        final Bundle bundle = new Bundle();

        final AikEd25519 aikEd = new AikEd25519();
        aikEd.setContent(new byte[]{0x01, 0x02});
        bundle.addExtension(aikEd);

        final AikMldsa aikMl = new AikMldsa();
        aikMl.setContent(new byte[]{0x03, 0x04});
        bundle.addExtension(aikMl);

        final Dc dc = new Dc();
        dc.setContent(new byte[]{0x05});
        bundle.addExtension(dc);

        final Ik ik = new Ik();
        ik.setContent(new byte[]{0x06});
        bundle.addExtension(ik);

        final Spk spk = new Spk();
        spk.setId(7);
        final SpkKey spkKey = new SpkKey();
        spkKey.setContent(new byte[]{0x07});
        spk.addExtension(spkKey);
        final SpkSig spkSig = new SpkSig();
        spkSig.setContent(new byte[]{0x08});
        spk.addExtension(spkSig);
        bundle.addExtension(spk);

        final Kemkeys kemkeys = new Kemkeys();
        final Kemkey kemkey = new Kemkey();
        kemkey.setId(1);
        final SpkKey kemKey = new SpkKey();
        kemKey.setContent(new byte[]{0x09});
        kemkey.addExtension(kemKey);
        final SpkSig kemSig = new SpkSig();
        kemSig.setContent(new byte[]{0x0B});
        kemkey.addExtension(kemSig);
        final KemMldsaSig kemMldsaSig = new KemMldsaSig();
        kemMldsaSig.setContent(new byte[]{0x0C});
        kemkey.addExtension(kemMldsaSig);
        kemkeys.addKemkey(kemkey);
        bundle.addExtension(kemkeys);

        final Opks opks = new Opks();
        final Opk opk = new Opk();
        opk.setId(2);
        opk.setContent(new byte[]{0x0A});
        opks.addOpk(opk);
        bundle.addExtension(opks);

        final String xml = StreamElementWriter.asString(bundle);

        Assert.assertTrue(xml.contains("bundle"));
        Assert.assertTrue(xml.contains("urn:xmppqr:x3dhpq:bundle:0"));
        Assert.assertTrue(xml.contains("aik-ed25519"));
        Assert.assertTrue(xml.contains("aik-mldsa"));
        Assert.assertTrue(xml.contains("spk"));
        Assert.assertTrue(xml.contains("id=\"7\""));
        Assert.assertTrue(xml.contains("kemkeys"));
        Assert.assertTrue(xml.contains("opks"));
        Assert.assertNotNull(bundle.getSpk());
        Assert.assertEquals(Integer.valueOf(7), bundle.getSpk().getId());
    }
}
