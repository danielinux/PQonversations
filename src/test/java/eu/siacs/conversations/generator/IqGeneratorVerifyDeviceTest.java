package eu.siacs.conversations.generator;

import eu.siacs.conversations.xml.Namespace;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.x3dhpq.pair.VerifyDevice;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.ConscryptMode;

/**
 * Round-trip test for the project-internal `<verify-device>` IQ-set used to
 * announce a freshly-bound resource to the user's other authenticated
 * resources (XEP §15.8).
 */
@RunWith(RobolectricTestRunner.class)
@ConscryptMode(ConscryptMode.Mode.OFF)
public class IqGeneratorVerifyDeviceTest {

    private static IqGenerator generator() {
        return new IqGenerator(null);
    }

    @Test
    public void verifyDevice_typeIsSet() {
        final Iq iq = generator().generateX3dhpqVerifyDevice(1234567);
        Assert.assertEquals(Iq.Type.SET, iq.getType());
    }

    @Test
    public void verifyDevice_hasVerifyDeviceChild() {
        final Iq iq = generator().generateX3dhpqVerifyDevice(1234567);
        final VerifyDevice verify = iq.getOnlyExtension(VerifyDevice.class);
        Assert.assertNotNull("expected <verify-device> child", verify);
        Assert.assertEquals(Namespace.X3DHPQ_PAIR, verify.getNamespace());
    }

    @Test
    public void verifyDevice_carriesDeviceId() {
        final Iq iq = generator().generateX3dhpqVerifyDevice(1234567);
        final VerifyDevice verify = iq.getOnlyExtension(VerifyDevice.class);
        Assert.assertEquals(Integer.valueOf(1234567), verify.getDeviceId());
    }

    @Test
    public void verifyDevice_transportIsMessage() {
        final Iq iq = generator().generateX3dhpqVerifyDevice(1);
        final VerifyDevice verify = iq.getOnlyExtension(VerifyDevice.class);
        Assert.assertEquals("message", verify.getTransport());
    }

}
