package eu.siacs.conversations.parser;

import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.xmpp.XmppConnection;
import eu.siacs.conversations.xmpp.manager.BlockingManager;
import eu.siacs.conversations.xmpp.manager.DiscoManager;
import eu.siacs.conversations.xmpp.manager.EntityTimeManager;
import eu.siacs.conversations.xmpp.manager.JingleManager;
import eu.siacs.conversations.xmpp.manager.MultiUserChatManager;
import eu.siacs.conversations.xmpp.manager.PingManager;
import eu.siacs.conversations.xmpp.manager.RosterManager;
import eu.siacs.conversations.xmpp.manager.UnifiedPushManager;
import im.conversations.android.xmpp.model.blocking.Block;
import im.conversations.android.xmpp.model.blocking.Unblock;
import im.conversations.android.xmpp.model.disco.info.InfoQuery;
import im.conversations.android.xmpp.model.error.Condition;
import im.conversations.android.xmpp.model.ibb.InBandByteStream;
import im.conversations.android.xmpp.model.jingle.Jingle;
import im.conversations.android.xmpp.model.ping.Ping;
import im.conversations.android.xmpp.model.stanza.Iq;
import im.conversations.android.xmpp.model.time.Time;
import im.conversations.android.xmpp.model.up.Push;
import java.util.function.Consumer;

public class IqParser extends AbstractParser implements Consumer<Iq> {

    public IqParser(final XmppConnectionService service, final XmppConnection connection) {
        super(service, connection);
    }

    @Override
    public void accept(final Iq packet) {
        final var type = packet.getType();
        switch (type) {
            case SET -> acceptPush(packet);
            case GET -> acceptRequest(packet);
            default ->
                    throw new AssertionError(
                            "IQ results and errors should are handled in callbacks");
        }
    }

    private void acceptPush(final Iq packet) {
        // there is rarely a good reason to respond to IQs from MUCs
        if (getManager(MultiUserChatManager.class).isMuc(packet)) {
            this.connection.sendErrorFor(packet, new Condition.ServiceUnavailable());
            return;
        }
        if (packet.hasExtension(Jingle.class)) {
            this.getManager(JingleManager.class).process(packet);
        } else if (packet.hasExtension(im.conversations.android.xmpp.model.roster.Query.class)) {
            this.getManager(RosterManager.class).push(packet);
        } else if (packet.hasExtension(Block.class)) {
            this.getManager(BlockingManager.class).pushBlock(packet);
        } else if (packet.hasExtension(Unblock.class)) {
            this.getManager(BlockingManager.class).pushUnblock(packet);
        } else if (packet.hasExtension(InBandByteStream.class)) {
            this.getManager(JingleManager.class).deliverIbbPacket(packet);
        } else if (packet.hasExtension(Push.class)) {
            this.getManager(UnifiedPushManager.class).push(packet);
        } else {
            this.connection.sendErrorFor(packet, new Condition.FeatureNotImplemented());
        }
    }

    private void acceptRequest(final Iq packet) {
        // responding to pings in MUCs is fine. this does not reveal more info than responding with
        // service unavailable
        if (packet.hasExtension(Ping.class)) {
            this.getManager(PingManager.class).pong(packet);
            return;
        }

        // there is rarely a good reason to respond to IQs from MUCs
        if (getManager(MultiUserChatManager.class).isMuc(packet)) {
            this.connection.sendErrorFor(packet, new Condition.ServiceUnavailable());
        } else if (packet.hasExtension(InfoQuery.class)) {
            this.getManager(DiscoManager.class).handleInfoQuery(packet);
        } else if (packet.hasExtension(im.conversations.android.xmpp.model.version.Query.class)) {
            this.getManager(DiscoManager.class).handleVersionRequest(packet);
        } else if (packet.hasExtension(Time.class)) {
            this.getManager(EntityTimeManager.class).request(packet);
        } else {
            this.connection.sendErrorFor(packet, new Condition.FeatureNotImplemented());
        }
    }
}
