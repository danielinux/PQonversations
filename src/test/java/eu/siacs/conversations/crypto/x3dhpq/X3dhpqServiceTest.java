package eu.siacs.conversations.crypto.x3dhpq;

import eu.siacs.conversations.xml.Namespace;
import eu.siacs.conversations.xmpp.Jid;
import im.conversations.android.xmpp.model.x3dhpq.devicelist.DeviceList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Assert;
import org.junit.Test;

public class X3dhpqServiceTest {

    // Parse a JID without real Android infra; Jid.of is pure-Java.
    private static final Jid FROM = Jid.of("alice@example.org");

    @Test
    public void handleEventRoutesDeviceListToListener() {
        // Arrange: construct service with no-arg test constructor (no Account/Service needed).
        final X3dhpqService service = new X3dhpqService();
        final AtomicBoolean called = new AtomicBoolean(false);
        final AtomicReference<DeviceList> received = new AtomicReference<>();

        service.setDeviceListListener(
                (from, list) -> {
                    called.set(true);
                    received.set(list);
                });

        final DeviceList payload = new DeviceList();
        payload.setVersion("1");

        // Act
        final boolean handled =
                service.handleEvent(FROM, Namespace.X3DHPQ_DEVICELIST, "current", payload);

        // Assert: handled returns true and listener was invoked with the correct payload.
        Assert.assertTrue("handleEvent should return true for X3DHPQ_DEVICELIST", handled);
        Assert.assertTrue("DeviceListListener should have been called", called.get());
        Assert.assertSame("Listener should receive the exact payload object", payload, received.get());
    }

    @Test
    public void handleEventReturnsFalseForUnknownNamespace() {
        // Arrange
        final X3dhpqService service = new X3dhpqService();

        // Act: send an event for a namespace that X3dhpqService does not own.
        final boolean handled =
                service.handleEvent(FROM, "urn:unknown:namespace", "item1", new DeviceList());

        // Assert
        Assert.assertFalse("handleEvent should return false for an unknown namespace", handled);
    }

    @Test
    public void listenerReplacementLastSetWins() {
        // Arrange: register a first listener, then replace it with a second.
        final X3dhpqService service = new X3dhpqService();
        final AtomicBoolean firstCalled = new AtomicBoolean(false);
        final AtomicBoolean secondCalled = new AtomicBoolean(false);

        service.setDeviceListListener((from, list) -> firstCalled.set(true));
        service.setDeviceListListener((from, list) -> secondCalled.set(true));

        final DeviceList payload = new DeviceList();

        // Act
        service.handleEvent(FROM, Namespace.X3DHPQ_DEVICELIST, "current", payload);

        // Assert: only the second (replacement) listener fires.
        Assert.assertFalse("First listener should not be called after replacement", firstCalled.get());
        Assert.assertTrue("Second (latest) listener should be called", secondCalled.get());
    }
}
