package eu.siacs.conversations.parser;

import android.util.Log;
import android.util.Pair;
import com.google.common.base.Strings;
import eu.siacs.conversations.AppSettings;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.crypto.x3dhpq.X3dhpqService;
import eu.siacs.conversations.crypto.x3dhpq.XmppX3dhpqMessage;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.entities.Contact;
import eu.siacs.conversations.entities.Conversation;
import eu.siacs.conversations.entities.Conversational;
import eu.siacs.conversations.entities.Message;
import eu.siacs.conversations.http.HttpConnectionManager;
import eu.siacs.conversations.services.XmppConnectionService;
import eu.siacs.conversations.utils.CryptoHelper;
import eu.siacs.conversations.xml.Element;
import eu.siacs.conversations.xml.LocalizedContent;
import eu.siacs.conversations.xml.Namespace;
import eu.siacs.conversations.xmpp.Jid;
import eu.siacs.conversations.xmpp.XmppConnection;
import eu.siacs.conversations.xmpp.jingle.JingleRtpConnection;
import eu.siacs.conversations.xmpp.manager.ActivityManager;
import eu.siacs.conversations.xmpp.manager.ChatStateManager;
import eu.siacs.conversations.xmpp.manager.DeliveryReceiptManager;
import eu.siacs.conversations.xmpp.manager.DisplayedManager;
import eu.siacs.conversations.xmpp.manager.JingleManager;
import eu.siacs.conversations.xmpp.manager.JingleMessageManager;
import eu.siacs.conversations.xmpp.manager.MessageArchiveManager;
import eu.siacs.conversations.xmpp.manager.ModerationManager;
import eu.siacs.conversations.xmpp.manager.MultiUserChatManager;
import eu.siacs.conversations.xmpp.manager.PubSubManager;
import eu.siacs.conversations.xmpp.manager.ReactionManager;
import eu.siacs.conversations.xmpp.manager.RosterManager;
import eu.siacs.conversations.xmpp.manager.StanzaIdManager;
import eu.siacs.conversations.xmpp.manager.VerifyDeviceManager;
import im.conversations.android.xmpp.model.Extension;
import im.conversations.android.xmpp.model.x3dhpq.envelope.Envelope;
import im.conversations.x3dhpq.protocol.PrekeyEnvelope;
import im.conversations.x3dhpq.protocol.Session;
import im.conversations.x3dhpq.protocol.SessionException;
import im.conversations.android.xmpp.model.carbons.Received;
import im.conversations.android.xmpp.model.carbons.Sent;
import im.conversations.android.xmpp.model.conference.DirectInvite;
import im.conversations.android.xmpp.model.correction.Replace;
import im.conversations.android.xmpp.model.fallback.Body;
import im.conversations.android.xmpp.model.fallback.Fallback;
import im.conversations.android.xmpp.model.forward.Forwarded;
import im.conversations.android.xmpp.model.jmi.JingleMessage;
import im.conversations.android.xmpp.model.mam.Result;
import im.conversations.android.xmpp.model.markers.Displayed;
import im.conversations.android.xmpp.model.markers.Markable;
import im.conversations.android.xmpp.model.muc.user.MucUser;
import im.conversations.android.xmpp.model.nick.Nick;
import im.conversations.android.xmpp.model.occupant.OccupantId;
import im.conversations.android.xmpp.model.oob.OutOfBandData;
import im.conversations.android.xmpp.model.pubsub.event.Event;
import im.conversations.android.xmpp.model.reactions.Reactions;
import im.conversations.android.xmpp.model.retraction.Retract;
import java.util.UUID;
import java.util.function.Consumer;

public class MessageParser extends AbstractParser
        implements Consumer<im.conversations.android.xmpp.model.stanza.Message> {

    public MessageParser(final XmppConnectionService service, final XmppConnection connection) {
        super(service, connection);
    }

    private Message parseX3dhpqChat(
            final Envelope envelopeEl,
            final Jid from,
            final Conversation conversation,
            final int status) {
        if (envelopeEl == null || from == null || conversation == null) {
            return null;
        }
        final X3dhpqService x3dhpqService = conversation.getAccount() != null
                ? conversation.getAccount().getX3dhpqService() : null;
        if (x3dhpqService == null) {
            Log.d(Config.LOGTAG, "x3dhpq: parseX3dhpqChat skipped — service is null");
            return null;
        }
        final XmppX3dhpqMessage incoming;
        try {
            incoming = XmppX3dhpqMessage.fromExtension(
                    conversation.getAccount(), from, envelopeEl);
        } catch (final Exception e) {
            Log.d(Config.LOGTAG, conversation.getAccount().getJid().asBareJid()
                    + ": invalid x3dhpq envelope: " + e.getMessage());
            // bad envelope → skip, don't persist a stub message
            return null;
        }

        final Integer myDeviceIdObj = x3dhpqService.getOwnDeviceIdOrNull();
        if (myDeviceIdObj == null) {
            Log.d(Config.LOGTAG, conversation.getAccount().getJid().asBareJid()
                    + ": x3dhpq received but local device not bootstrapped yet; skipping");
            return null;
        }
        final int myDeviceId = myDeviceIdObj;
        final XmppX3dhpqMessage.EncryptedKey k = incoming.findKeyForDevice(myDeviceId);
        if (k == null) {
            // envelope addressed to other devices only — nothing to do for us
            return null;
        }

        final Session session;
        try {
            if (k.prekey != null) {
                // first-time inbound: run PQXDH responder, build new Session
                final PrekeyEnvelope env = new PrekeyEnvelope(
                        k.prekey.ephemeralPub,
                        k.prekey.kemCiphertext,
                        k.prekey.kemKeyId,
                        k.prekey.opkId,
                        k.prekey.dcMarshal,
                        k.prekey.aikEd25519Pub,
                        k.prekey.aikMldsaPub);
                session = x3dhpqService.acceptInboundSessionAsSession(
                        from, incoming.senderDeviceId, env);
            } else {
                session = x3dhpqService.loadSession(from, incoming.senderDeviceId);
                if (session == null) {
                    // out-of-band: peer references a session we don't have. This is
                    // common during MAM catchup of messages that pre-date our local
                    // bootstrap. Skip rather than persist a fake "FAILED" message.
                    Log.d(Config.LOGTAG, conversation.getAccount().getJid().asBareJid()
                            + ": no x3dhpq session found for " + from + "/" + incoming.senderDeviceId);
                    return null;
                }
            }
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, conversation.getAccount().getJid().asBareJid()
                    + ": x3dhpq session setup failed: " + e.getMessage());
            return null;
        }

        if (session == null) {
            return null;
        }

        final byte[] plaintext;
        try {
            plaintext = incoming.decrypt(session, k);
        } catch (final Exception e) {
            // Catch broader than SessionException: any unexpected failure during
            // decrypt (NPE, IllegalStateException, etc.) must not propagate up
            // and crash the parser pipeline.
            Log.w(Config.LOGTAG, conversation.getAccount().getJid().asBareJid()
                    + ": x3dhpq decrypt failed: " + e.getMessage());
            return null;
        }

        // persist updated session state after successful decrypt
        try {
            x3dhpqService.persistSession(from, incoming.senderDeviceId, session);
        } catch (final Exception e) {
            Log.w(Config.LOGTAG, "x3dhpq: persistSession failed: " + e.getMessage());
            // not fatal — message decryption succeeded
        }

        return new Message(
                conversation,
                new String(plaintext, java.nio.charset.StandardCharsets.UTF_8),
                Message.ENCRYPTION_X3DHPQ,
                status);
    }

    /** Decrypt a group-encrypted message using the room's GroupCryptoService. */
    private Message parseX3dhpqGroupChat(
            final im.conversations.android.xmpp.model.x3dhpq.envelope.EnvelopeGroup groupEnv,
            final Jid from,
            final Conversation conversation,
            final int status) {
        if (groupEnv == null || from == null || conversation == null) return null;
        final eu.siacs.conversations.crypto.x3dhpq.GroupCryptoService gcs =
                conversation.getAccount() != null
                        ? mXmppConnectionService.getGroupCryptoService(conversation.getAccount())
                        : null;
        if (gcs == null) {
            Log.d(Config.LOGTAG, "x3dhpq group: GroupCryptoService is null");
            return null;
        }
        final byte[] plaintext;
        try {
            plaintext = gcs.decryptGroupMessage(conversation.getAddress().asBareJid(), groupEnv);
        } catch (eu.siacs.conversations.crypto.x3dhpq.GroupCryptoService.GroupNotEnabledException e) {
            Log.d(Config.LOGTAG, conversation.getAccount().getJid().asBareJid()
                    + ": x3dhpq group not enabled for " + conversation.getAddress()
                    + ": " + e.getMessage());
            return null;
        } catch (Exception e) {
            Log.w(Config.LOGTAG, conversation.getAccount().getJid().asBareJid()
                    + ": x3dhpq group decrypt failed: " + e.getMessage());
            return null;
        }
        if (plaintext == null) {
            // Deferred — announcement not yet received
            return null;
        }
        return new Message(
                conversation,
                new String(plaintext, java.nio.charset.StandardCharsets.UTF_8),
                Message.ENCRYPTION_X3DHPQ,
                status);
    }

    /**
     * Handle an inbound pairwise envelope whose {@code <payload>} has {@code type='sender-chain'}.
     * Decrypts the transport key, then decrypts the payload, and hands the
     * {@link im.conversations.x3dhpq.types.SenderChainAnnouncement} bytes to GroupCryptoService.
     */
    private void parseX3dhpqSenderChain(
            final im.conversations.android.xmpp.model.x3dhpq.envelope.Envelope envelopeEl,
            final Jid from,
            final eu.siacs.conversations.entities.Account account) {
        final X3dhpqService x3dhpqService = account.getX3dhpqService();
        if (x3dhpqService == null) return;
        final Integer myDeviceIdObj = x3dhpqService.getOwnDeviceIdOrNull();
        if (myDeviceIdObj == null) return;
        final int myDeviceId = myDeviceIdObj;

        final XmppX3dhpqMessage incoming;
        try {
            incoming = XmppX3dhpqMessage.fromExtension(account, from, envelopeEl);
        } catch (Exception e) {
            Log.d(Config.LOGTAG, account.getJid().asBareJid()
                    + ": invalid x3dhpq sender-chain envelope: " + e.getMessage());
            return;
        }

        final XmppX3dhpqMessage.EncryptedKey k = incoming.findKeyForDevice(myDeviceId);
        if (k == null) return;

        final im.conversations.x3dhpq.protocol.Session session;
        try {
            if (k.prekey != null) {
                final im.conversations.x3dhpq.protocol.PrekeyEnvelope env =
                        new im.conversations.x3dhpq.protocol.PrekeyEnvelope(
                                k.prekey.ephemeralPub, k.prekey.kemCiphertext,
                                k.prekey.kemKeyId, k.prekey.opkId, k.prekey.dcMarshal,
                                k.prekey.aikEd25519Pub, k.prekey.aikMldsaPub);
                session = x3dhpqService.acceptInboundSessionAsSession(from, incoming.senderDeviceId, env);
            } else {
                session = x3dhpqService.loadSession(from, incoming.senderDeviceId);
                if (session == null) return;
            }
        } catch (Exception e) {
            Log.w(Config.LOGTAG, account.getJid().asBareJid()
                    + ": x3dhpq sender-chain session setup failed: " + e.getMessage());
            return;
        }

        final byte[] annBytes;
        try {
            annBytes = incoming.decrypt(session, k);
        } catch (Exception e) {
            Log.w(Config.LOGTAG, account.getJid().asBareJid()
                    + ": x3dhpq sender-chain decrypt failed: " + e.getMessage());
            return;
        }

        try {
            x3dhpqService.persistSession(from, incoming.senderDeviceId, session);
        } catch (Exception ignored) {}

        // Forward to GroupCryptoService
        final eu.siacs.conversations.crypto.x3dhpq.GroupCryptoService gcs =
                mXmppConnectionService.getGroupCryptoService(account);
        if (gcs != null) {
            gcs.onSenderChainAnnouncementReceived(from, incoming.senderDeviceId, annBytes);
        }
    }

    private boolean handleErrorMessage(
            final Account account,
            final im.conversations.android.xmpp.model.stanza.Message packet) {
        if (packet.getType() == im.conversations.android.xmpp.model.stanza.Message.Type.ERROR) {
            if (packet.fromServer(account)) {
                final var forwarded =
                        getForwardedMessagePacket(packet, "received", Namespace.CARBONS);
                if (forwarded != null) {
                    return handleErrorMessage(account, forwarded.first);
                }
            }
            final Jid from = packet.getFrom();
            final String id = packet.getId();
            if (from != null && id != null) {
                if (id.startsWith(JingleRtpConnection.JINGLE_MESSAGE_PROPOSE_ID_PREFIX)) {
                    final String sessionId =
                            id.substring(
                                    JingleRtpConnection.JINGLE_MESSAGE_PROPOSE_ID_PREFIX.length());
                    getManager(JingleManager.class)
                            .updateProposedSessionDiscovered(
                                    from, sessionId, JingleManager.DeviceDiscoveryState.FAILED);
                    return true;
                }
                if (id.startsWith(JingleRtpConnection.JINGLE_MESSAGE_PROCEED_ID_PREFIX)) {
                    final String sessionId =
                            id.substring(
                                    JingleRtpConnection.JINGLE_MESSAGE_PROCEED_ID_PREFIX.length());
                    final String message = extractErrorMessage(packet);
                    getManager(JingleManager.class).failProceed(from, sessionId, message);
                    return true;
                }
                mXmppConnectionService.markMessage(
                        account,
                        from.asBareJid(),
                        id,
                        Message.STATUS_SEND_FAILED,
                        extractErrorMessage(packet));
                final Element error = packet.findChild("error");
                final boolean pingWorthyError =
                        error != null
                                && (error.hasChild("not-acceptable")
                                        || error.hasChild("remote-server-timeout")
                                        || error.hasChild("remote-server-not-found"));
                if (pingWorthyError) {
                    Conversation conversation = mXmppConnectionService.find(account, from);
                    if (conversation != null
                            && conversation.getMode() == Conversational.MODE_MULTI) {
                        if (getManager(MultiUserChatManager.class)
                                .getOrCreateState(conversation)
                                .online()) {
                            Log.d(
                                    Config.LOGTAG,
                                    account.getJid().asBareJid()
                                            + ": received ping worthy error for seemingly online"
                                            + " muc at "
                                            + from);
                            getManager(MultiUserChatManager.class).pingAndRejoin(conversation);
                        }
                    }
                }
            }
            return true;
        }
        return false;
    }

    @Override
    public void accept(final im.conversations.android.xmpp.model.stanza.Message original) {
        final var originalFrom = original.getFrom();
        final var account = this.getAccount();
        if (handleErrorMessage(account, original)) {
            return;
        }
        final im.conversations.android.xmpp.model.stanza.Message packet;
        Long timestamp = null;
        boolean isCarbon = false;
        String serverMsgId = null;
        final var result = original.getExtension(Result.class);
        final String queryId = result == null ? null : result.getQueryId();
        final MessageArchiveManager.Query query =
                queryId == null ? null : getManager(MessageArchiveManager.class).findQuery(queryId);
        final boolean offlineMessagesRetrieved = connection.isOfflineMessagesRetrieved();
        if (query != null
                && getManager(MessageArchiveManager.class).validFrom(query, original.getFrom())) {
            final var f = result.getForwarded();
            final var stamp = f == null ? null : f.getStamp();
            final var m = f == null ? null : f.getMessage();
            if (stamp == null || m == null) {
                return;
            }

            timestamp = stamp.toEpochMilli();
            packet = m;
            serverMsgId = result.getId();
            query.incrementMessageCount();

            if (query.isImplausibleFrom(packet.getFrom())) {
                Log.d(Config.LOGTAG, "found implausible from in MUC MAM archive");
                return;
            }

            if (handleErrorMessage(account, packet)) {
                return;
            }
        } else if (query != null) {
            Log.d(
                    Config.LOGTAG,
                    account.getJid().asBareJid()
                            + ": received mam result with invalid from ("
                            + original.getFrom()
                            + ") or queryId ("
                            + queryId
                            + ")");
            return;
        } else if (original.fromServer(account)
                && original.getType()
                        != im.conversations.android.xmpp.model.stanza.Message.Type.GROUPCHAT) {
            Pair<im.conversations.android.xmpp.model.stanza.Message, Long> f;
            f = getForwardedMessagePacket(original, Received.class);
            f = f == null ? getForwardedMessagePacket(original, Sent.class) : f;
            packet = f != null ? f.first : original;
            if (handleErrorMessage(account, packet)) {
                return;
            }
            timestamp = f != null ? f.second : null;
            isCarbon = f != null;
        } else {
            packet = original;
        }

        if (timestamp == null) {
            timestamp =
                    AbstractParser.parseTimestamp(original, AbstractParser.parseTimestamp(packet));
        }
        final LocalizedContent body = packet.getBody();
        final Element mucUserElement = packet.findChild("x", Namespace.MUC_USER);
        final boolean isTypeGroupChat =
                packet.getType()
                        == im.conversations.android.xmpp.model.stanza.Message.Type.GROUPCHAT;
        final var encrypted =
                packet.getOnlyExtension(im.conversations.android.xmpp.model.pgp.Encrypted.class);
        final String pgpEncrypted = encrypted == null ? null : encrypted.getContent();

        final var oob = packet.getExtension(OutOfBandData.class);
        final String oobUrl = oob != null ? oob.getURL() : null;
        final var replace = packet.getExtension(Replace.class);
        final var replacementId = replace == null ? null : replace.getId();
        final var x3dhpqEnvelope = packet.getOnlyExtension(Envelope.class);
        final var x3dhpqGroupEnvelope = packet.getOnlyExtension(
                im.conversations.android.xmpp.model.x3dhpq.envelope.EnvelopeGroup.class);
        // TODO this can probably be refactored to be final
        int status;
        final Jid counterpart;
        final Jid to = packet.getTo();
        final Jid from = packet.getFrom();
        final Element originId = packet.findChild("origin-id", Namespace.STANZA_IDS);
        final String remoteMsgId;
        if (originId != null && originId.getAttribute("id") != null) {
            remoteMsgId = originId.getAttribute("id");
        } else {
            remoteMsgId = packet.getId();
        }
        boolean notify = false;

        if (from == null || !Jid.Invalid.isValid(from) || !Jid.Invalid.isValid(to)) {
            Log.e(Config.LOGTAG, "encountered invalid message from='" + from + "' to='" + to + "'");
            return;
        }
        if (query != null && !query.muc() && isTypeGroupChat) {
            Log.e(
                    Config.LOGTAG,
                    account.getJid().asBareJid()
                            + ": received group chat ("
                            + from
                            + ") message on regular MAM request. skipping");
            return;
        }
        final boolean selfAddressed;
        if (packet.fromAccount(account)) {
            status = Message.STATUS_SEND;
            selfAddressed = to == null || account.getJid().asBareJid().equals(to.asBareJid());
            if (selfAddressed) {
                counterpart = from;
            } else {
                counterpart = to;
            }
        } else {
            status = Message.STATUS_RECEIVED;
            counterpart = from;
            selfAddressed = false;
        }

        // x3dhpq serverless rendezvous (§10.1a, method A): a directed <message> carrying
        // <pair-hello> triggers the existing device to initiate pairing. Consume it here.
        if (packet.hasExtension(im.conversations.android.xmpp.model.x3dhpq.pair.PairHello.class)) {
            final var hello =
                    packet.getExtension(
                            im.conversations.android.xmpp.model.x3dhpq.pair.PairHello.class);
            getManager(VerifyDeviceManager.class).handlePairHello(hello);
            return;
        }

        // x3dhpq pairing stanzas (chat-type <message> carrying <pair>): dispatch to FSM and
        // consume — do not fall through to body/message-archive handlers.
        if (packet.hasExtension(im.conversations.android.xmpp.model.x3dhpq.pair.Pair.class)) {
            final var pairing = account.getPairingSessionService();
            if (pairing != null) {
                try {
                    pairing.onIncoming(packet);
                } catch (final Exception e) {
                    Log.w(Config.LOGTAG, "x3dhpq pairing dispatch failed", e);
                }
            }
            return;
        }

        if (packet.hasExtension(MucUser.class)
                && packet.getExtension(MucUser.class)
                        .hasExtension(im.conversations.android.xmpp.model.muc.user.Invite.class)) {
            if (getManager(MultiUserChatManager.class).handleMediatedInvite(packet)) {
                return;
            }
        }
        if (packet.hasExtension(DirectInvite.class)) {
            if (getManager(MultiUserChatManager.class).handleDirectInvite(packet)) {
                return;
            }
        }

        if (original.hasExtension(MucUser.class)) {
            if (getManager(MultiUserChatManager.class).handleStatusMessage(original)) {
                return;
            }
        }
        final boolean bodyIsFallback;
        if (body != null && packet.hasExtension(Reactions.class)) {
            final var range = Fallback.get(packet, Reactions.class, Body.class);
            bodyIsFallback = range.isPresent() && range.get().isEntire(body);
        } else if (body != null && packet.hasExtension(Retract.class)) {
            final var range = Fallback.get(packet, Retract.class, Body.class);
            bodyIsFallback = range.isPresent() && range.get().isEntire(body);
        } else {
            bodyIsFallback = false;
        }

        if ((body != null && !bodyIsFallback)
                || pgpEncrypted != null
                || x3dhpqEnvelope != null
                || x3dhpqGroupEnvelope != null
                || oobUrl != null) {
            final boolean conversationIsProbablyMuc =
                    isTypeGroupChat
                            || mucUserElement != null
                            || connection
                                    .getMucServersWithholdAccount()
                                    .contains(counterpart.getDomain());
            final Conversation conversation =
                    mXmppConnectionService.findOrCreateConversation(
                            account,
                            counterpart.asBareJid(),
                            conversationIsProbablyMuc,
                            false,
                            query,
                            false);
            final boolean conversationMultiMode = conversation.getMode() == Conversation.MODE_MULTI;

            if (serverMsgId == null) {
                serverMsgId =
                        getManager(StanzaIdManager.class)
                                .get(packet, isTypeGroupChat, conversation);
            }

            if (selfAddressed) {
                // don’t store serverMsgId on reflections for edits
                final var reflectedServerMsgId =
                        Strings.isNullOrEmpty(replacementId) ? serverMsgId : null;
                if (mXmppConnectionService.markMessage(
                        conversation,
                        remoteMsgId,
                        Message.STATUS_SEND_RECEIVED,
                        reflectedServerMsgId)) {
                    return;
                }
                status = Message.STATUS_RECEIVED;
                if (remoteMsgId != null
                        && conversation.findMessageWithRemoteId(remoteMsgId, counterpart) != null) {
                    return;
                }
            }

            if (isTypeGroupChat) {
                // this should probably remain a counterpart check
                if (getManager(MultiUserChatManager.class)
                        .getOrCreateState(conversation)
                        .isSelf(counterpart)) {
                    status = Message.STATUS_SEND_RECEIVED;
                    isCarbon = true; // not really carbon but received from another resource
                    // don’t store serverMsgId on reflections for edits
                    final var reflectedServerMsgId =
                            Strings.isNullOrEmpty(replacementId) ? serverMsgId : null;
                    if (mXmppConnectionService.markMessage(
                            conversation, remoteMsgId, status, reflectedServerMsgId, body)) {
                        return;
                    } else if (remoteMsgId == null || Config.IGNORE_ID_REWRITE_IN_MUC) {
                        if (body != null) {
                            Message message = conversation.findSentMessageWithBody(body.content);
                            if (message != null) {
                                mXmppConnectionService.markMessage(message, status);
                                return;
                            }
                        }
                    }
                } else {
                    final var user =
                            getManager(MultiUserChatManager.class).getMucUser(packet, query);
                    if (user != null) {
                        final var mucOptions =
                                getManager(MultiUserChatManager.class).getState(from.asBareJid());
                        if (mucOptions != null && mucOptions.isOurAccount(user)) {
                            status = Message.STATUS_SEND_RECEIVED;
                            isCarbon = true;
                        } else {
                            status = Message.STATUS_RECEIVED;
                        }
                    } else {
                        status = Message.STATUS_RECEIVED;
                    }
                }
            }
            final Message message;
            if (pgpEncrypted != null) {
                message = new Message(conversation, pgpEncrypted, Message.ENCRYPTION_PGP, status);
            } else if (x3dhpqGroupEnvelope != null && isTypeGroupChat) {
                // §13 group-encrypted message: decrypt via GroupCryptoService.
                try {
                    message = parseX3dhpqGroupChat(x3dhpqGroupEnvelope, from, conversation, status);
                } catch (final Throwable t) {
                    Log.e(Config.LOGTAG, account.getJid().asBareJid()
                            + ": x3dhpq group parser threw: " + t.getMessage(), t);
                    return;
                }
                if (message == null) {
                    return;
                }
            } else if (x3dhpqEnvelope != null) {
                // x3dhpq pairwise encrypted message (Wave D6). Wrap in a Throwable
                // catch so any unforeseen runtime error inside the crypto stack
                // (NPE on missing state, ML-DSA verification errors, malformed
                // session blobs after schema bumps, etc.) cannot crash the whole
                // process or the entire MessageParser pipeline.
                // First check for sender-chain announcement payload.
                try {
                    final var payloadEl = x3dhpqEnvelope.getPayload();
                    if (payloadEl != null && payloadEl.isSenderChain()) {
                        parseX3dhpqSenderChain(x3dhpqEnvelope, from, account);
                        return;
                    }
                    message = parseX3dhpqChat(x3dhpqEnvelope, from, conversation, status);
                } catch (final Throwable t) {
                    Log.e(Config.LOGTAG, account.getJid().asBareJid()
                            + ": x3dhpq parser threw: " + t.getMessage(), t);
                    return;
                }
                if (message == null) {
                    return;
                }
            } else if (body == null && oobUrl != null) {
                message = new Message(conversation, oobUrl, Message.ENCRYPTION_NONE, status);
                message.setOob(true);
                if (CryptoHelper.isPgpEncryptedUrl(oobUrl)) {
                    message.setEncryption(Message.ENCRYPTION_DECRYPTED);
                }
            } else {
                message = new Message(conversation, body.content, Message.ENCRYPTION_NONE, status);
                if (body.count > 1) {
                    message.setBodyLanguage(body.language);
                }
            }

            message.setCounterpart(counterpart);
            message.setRemoteMsgId(remoteMsgId);
            message.setServerMsgId(serverMsgId);
            message.setCarbon(isCarbon);
            message.setTime(timestamp);
            if (body != null && body.content != null && body.content.equals(oobUrl)) {
                message.setOob(true);
                if (CryptoHelper.isPgpEncryptedUrl(oobUrl)) {
                    message.setEncryption(Message.ENCRYPTION_DECRYPTED);
                }
            }
            message.markable = packet.hasExtension(Markable.class);
            if (conversationMultiMode) {
                final var mucOptions =
                        getManager(MultiUserChatManager.class).getOrCreateState(conversation);
                final var occupantId =
                        mucOptions.occupantId() ? packet.getOnlyExtension(OccupantId.class) : null;
                if (occupantId != null) {
                    message.setOccupantId(occupantId.getId());
                }
                final var user = getManager(MultiUserChatManager.class).getMucUser(packet, query);
                final var trueCounterpart = user == null ? null : user.getRealJid();
                message.setTrueCounterpart(trueCounterpart);
                if (!isTypeGroupChat) {
                    message.setType(Message.TYPE_PRIVATE);
                }
            } else {
                updateLastseen(account, from);
            }

            if (replacementId != null && mXmppConnectionService.allowMessageCorrection()) {
                final Message replacedMessage =
                        conversation.findMessageWithRemoteIdAndCounterpart(
                                replacementId,
                                counterpart,
                                message.getStatus() == Message.STATUS_RECEIVED,
                                message.isCarbon());
                if (replacedMessage != null) {
                    final boolean fingerprintsMatch =
                            replacedMessage.getFingerprint() == null
                                    || replacedMessage
                                            .getFingerprint()
                                            .equals(message.getFingerprint());
                    final boolean trueCountersMatch =
                            replacedMessage.getTrueCounterpart() != null
                                    && message.getTrueCounterpart() != null
                                    && replacedMessage
                                            .getTrueCounterpart()
                                            .asBareJid()
                                            .equals(message.getTrueCounterpart().asBareJid());
                    final boolean occupantIdMatch =
                            replacedMessage.getOccupantId() != null
                                    && replacedMessage
                                            .getOccupantId()
                                            .equals(message.getOccupantId());
                    final boolean duplicate = conversation.hasDuplicateMessage(message);
                    if (fingerprintsMatch
                            && (trueCountersMatch || occupantIdMatch || !conversationMultiMode)
                            && !duplicate) {
                        synchronized (replacedMessage) {
                            final String uuid = replacedMessage.getUuid();
                            replacedMessage.setUuid(UUID.randomUUID().toString());
                            replacedMessage.setBody(message.getBody());
                            // we store the IDs of the replacing message. This is essentially unused
                            // today (only the fact that there are _some_ edits causes the edit icon
                            // to appear)
                            replacedMessage.putEdited(
                                    message.getRemoteMsgId(), message.getServerMsgId());

                            // we used to call
                            // `replacedMessage.setServerMsgId(message.getServerMsgId());` so during
                            // catchup we could start from the edit; not the original message
                            // however this caused problems for things like reactions that refer to
                            // the serverMsgId

                            replacedMessage.setEncryption(message.getEncryption());
                            if (replacedMessage.getStatus() == Message.STATUS_RECEIVED) {
                                replacedMessage.markUnread();
                            }
                            getManager(ChatStateManager.class).process(packet);
                            mXmppConnectionService.updateMessage(replacedMessage, uuid);
                            if (replacedMessage.getStatus() == Message.STATUS_RECEIVED
                                    && (replacedMessage.trusted()
                                            || replacedMessage
                                                    .isPrivateMessage()) // TODO do we really want
                                    // to send receipts for all
                                    // PMs?
                                    && remoteMsgId != null
                                    && !selfAddressed
                                    && !isTypeGroupChat) {
                                getManager(DeliveryReceiptManager.class)
                                        .processRequest(packet, query);
                            }
                            if (replacedMessage.getEncryption() == Message.ENCRYPTION_PGP) {
                                conversation
                                        .getAccount()
                                        .getPgpDecryptionService()
                                        .discard(replacedMessage);
                                conversation
                                        .getAccount()
                                        .getPgpDecryptionService()
                                        .decrypt(replacedMessage, false);
                            }
                        }
                        mXmppConnectionService.getNotificationService().updateNotification();
                        return;
                    } else {
                        Log.d(
                                Config.LOGTAG,
                                account.getJid().asBareJid()
                                        + ": received message correction but verification didn't"
                                        + " check out");
                    }
                }
            }

            long deletionDate = mXmppConnectionService.getAutomaticMessageDeletionDate();
            if (deletionDate != 0 && message.getTimeSent() < deletionDate) {
                Log.d(
                        Config.LOGTAG,
                        account.getJid().asBareJid()
                                + ": skipping message from "
                                + message.getCounterpart().toString()
                                + " because it was sent prior to our deletion date");
                return;
            }

            boolean checkForDuplicates =
                    (isTypeGroupChat && packet.hasChild("delay", "urn:xmpp:delay"))
                            || message.isPrivateMessage()
                            || message.getServerMsgId() != null
                            || (query == null
                                    && getManager(MessageArchiveManager.class)
                                            .isCatchupInProgress(conversation));
            if (checkForDuplicates) {
                final Message duplicate = conversation.findDuplicateMessage(message);
                if (duplicate != null) {
                    final boolean serverMsgIdUpdated;
                    if (duplicate.getStatus() != Message.STATUS_RECEIVED
                            && duplicate.getUuid().equals(message.getRemoteMsgId())
                            && duplicate.getServerMsgId() == null
                            && message.getServerMsgId() != null) {
                        duplicate.setServerMsgId(message.getServerMsgId());
                        if (mXmppConnectionService.databaseBackend.updateMessage(
                                duplicate, false)) {
                            serverMsgIdUpdated = true;
                        } else {
                            serverMsgIdUpdated = false;
                            Log.e(Config.LOGTAG, "failed to update message");
                        }
                    } else {
                        serverMsgIdUpdated = false;
                    }
                    Log.d(
                            Config.LOGTAG,
                            "skipping duplicate message with "
                                    + message.getCounterpart()
                                    + ". serverMsgIdUpdated="
                                    + serverMsgIdUpdated);
                    return;
                }
            }

            if (query != null
                    && query.getPagingOrder() == MessageArchiveManager.PagingOrder.REVERSE) {
                conversation.prepend(query.getActualInThisQuery(), message);
            } else {
                conversation.add(message);
            }
            if (query != null) {
                query.incrementActualMessageCount();
            }

            if (query == null || query.isCatchup()) { // either no mam or catchup
                if (status == Message.STATUS_SEND || status == Message.STATUS_SEND_RECEIVED) {
                    mXmppConnectionService.markRead(conversation);
                    if (query == null) {
                        getManager(ActivityManager.class)
                                .record(from, ActivityManager.ActivityType.MESSAGE);
                    }
                } else {
                    message.markUnread();
                    notify = true;
                }
            }

            if (message.getEncryption() == Message.ENCRYPTION_PGP) {
                notify =
                        conversation
                                .getAccount()
                                .getPgpDecryptionService()
                                .decrypt(message, notify);
            }

            if (query == null) {
                getManager(ChatStateManager.class).process(packet);
            }

            if (message.getStatus() == Message.STATUS_RECEIVED
                    && (message.trusted() || message.isPrivateMessage())
                    && remoteMsgId != null
                    && !selfAddressed
                    && !isTypeGroupChat) {
                getManager(DeliveryReceiptManager.class).processRequest(packet, query);
            }

            mXmppConnectionService.databaseBackend.createMessage(message);
            final HttpConnectionManager manager =
                    this.mXmppConnectionService.getHttpConnectionManager();
            final var autoAcceptFileSize =
                    new AppSettings(mXmppConnectionService).getAutoAcceptFileSize();
            if (message.trusted()
                    && message.treatAsDownloadable()
                    && autoAcceptFileSize.isPresent()) {
                manager.createNewDownloadConnection(message);
            } else if (notify) {
                if (query != null && query.isCatchup()) {
                    mXmppConnectionService.getNotificationService().pushFromBacklog(message);
                } else {
                    mXmppConnectionService.getNotificationService().push(message);
                }
            }
            this.mXmppConnectionService.updateConversationUi();
        } else { // no body

            final var conversation = mXmppConnectionService.find(account, counterpart.asBareJid());

            if (query == null) {
                getManager(ChatStateManager.class).process(packet);
            }

            if (isTypeGroupChat) {
                if (packet.hasChild("subject")
                        && !packet.hasChild("thread")) { // We already know it has no body per above
                    if (conversation != null && conversation.getMode() == Conversation.MODE_MULTI) {
                        conversation.setHasMessagesLeftOnServer(conversation.countMessages() > 0);
                        final LocalizedContent subject = packet.getSubject();
                        if (subject != null
                                && getManager(MultiUserChatManager.class)
                                        .getOrCreateState(conversation)
                                        .setSubject(subject.content)) {
                            mXmppConnectionService.updateConversation(conversation);
                        }
                        mXmppConnectionService.updateConversationUi();
                        return;
                    }
                }
            }

            // begin JMI parsing
            if (packet.hasExtension(JingleMessage.class)) {
                getManager(JingleMessageManager.class)
                        .processJingleMessage(
                                packet,
                                counterpart,
                                query,
                                offlineMessagesRetrieved,
                                serverMsgId,
                                timestamp,
                                status);
            }

            if (packet.hasExtension(im.conversations.android.xmpp.model.receipts.Received.class)) {
                getManager(DeliveryReceiptManager.class).processReceived(packet, query);
            }

            if (packet.hasExtension(Displayed.class)) {
                getManager(DisplayedManager.class)
                        .processDisplayed(packet, selfAddressed, counterpart, query);
            }

            if (packet.hasExtension(Reactions.class)) {
                getManager(ReactionManager.class).processReactions(packet, counterpart, query);
            }

            if (original.hasExtension(Retract.class)
                    && originalFrom != null
                    && originalFrom.isBareJid()) {
                getManager(ModerationManager.class).handleRetraction(original);
            }

            // end no body
        }

        if (original.hasExtension(Event.class)) {
            getManager(PubSubManager.class).handleEvent(original);
        }

        final var nick = packet.getExtension(Nick.class);
        if (nick != null && Jid.Invalid.isValid(from)) {
            if (getManager(MultiUserChatManager.class).isMuc(from)) {
                return;
            }
            final Contact contact = account.getRoster().getContact(from);
            if (contact.setPresenceName(nick.getContent())) {
                connection.getManager(RosterManager.class).writeToDatabaseAsync();
                mXmppConnectionService.getAvatarService().clear(contact);
            }
        }
    }

    private static Pair<im.conversations.android.xmpp.model.stanza.Message, Long>
            getForwardedMessagePacket(
                    final im.conversations.android.xmpp.model.stanza.Message original,
                    Class<? extends Extension> clazz) {
        final var extension = original.getExtension(clazz);
        final var forwarded = extension == null ? null : extension.getExtension(Forwarded.class);
        if (forwarded == null) {
            return null;
        }
        final Long timestamp = AbstractParser.parseTimestamp(forwarded, null);
        final var forwardedMessage = forwarded.getMessage();
        if (forwardedMessage == null) {
            return null;
        }
        return new Pair<>(forwardedMessage, timestamp);
    }

    private static Pair<im.conversations.android.xmpp.model.stanza.Message, Long>
            getForwardedMessagePacket(
                    final im.conversations.android.xmpp.model.stanza.Message original,
                    final String name,
                    final String namespace) {
        final Element wrapper = original.findChild(name, namespace);
        final var forwardedElement =
                wrapper == null ? null : wrapper.findChild("forwarded", Namespace.FORWARD);
        if (forwardedElement instanceof Forwarded forwarded) {
            final Long timestamp = AbstractParser.parseTimestamp(forwarded, null);
            final var forwardedMessage = forwarded.getMessage();
            if (forwardedMessage == null) {
                return null;
            }
            return new Pair<>(forwardedMessage, timestamp);
        }
        return null;
    }
}
