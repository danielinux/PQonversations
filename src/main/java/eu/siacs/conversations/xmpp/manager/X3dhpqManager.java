package eu.siacs.conversations.xmpp.manager;

import android.content.Context;
import android.util.Log;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.xmpp.Jid;
import eu.siacs.conversations.xmpp.XmppConnection;
import im.conversations.android.xmpp.model.pubsub.Items;

/**
 * Manager that bridges PEP event Items to X3dhpqService for x3dhpq namespaces.
 */
public class X3dhpqManager extends AbstractManager {

    public X3dhpqManager(final Context context, final XmppConnection connection) {
        super(context, connection);
    }

    public void handleItems(final Jid from, final Items items) {
        final var account = getAccount();
        final var service = account.getX3dhpqService();
        if (service == null) {
            Log.d(Config.LOGTAG, "X3dhpqManager: no service for account, dropping items");
            return;
        }
        service.handleItems(from, items);
    }
}
