package eu.siacs.conversations.persistance;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Environment;
import android.os.SystemClock;
import android.util.Base64;
import android.util.Log;
import com.google.common.base.Stopwatch;
import com.google.common.base.Strings;
import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import eu.siacs.conversations.Config;
import eu.siacs.conversations.crypto.axolotl.AxolotlService;
import eu.siacs.conversations.crypto.axolotl.FingerprintStatus;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.entities.Contact;
import eu.siacs.conversations.entities.Conversation;
import eu.siacs.conversations.entities.IndividualMessage;
import eu.siacs.conversations.entities.Message;
import eu.siacs.conversations.entities.PresenceTemplate;
import eu.siacs.conversations.services.QuickConversationsService;
import eu.siacs.conversations.services.ShortcutService;
import eu.siacs.conversations.utils.CryptoHelper;
import eu.siacs.conversations.utils.CursorUtils;
import eu.siacs.conversations.utils.FtsUtils;
import eu.siacs.conversations.utils.MimeUtils;
import eu.siacs.conversations.utils.Resolver;
import eu.siacs.conversations.xmpp.Jid;
import eu.siacs.conversations.xmpp.mam.MamReference;
import im.conversations.android.xml.XmlElementReader;
import im.conversations.android.xmpp.EntityCapabilities;
import im.conversations.android.xmpp.EntityCapabilities2;
import im.conversations.android.xmpp.StreamElementWriter;
import im.conversations.android.xmpp.model.disco.info.InfoQuery;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import org.json.JSONObject;
import org.jxmpp.jid.parts.Localpart;
import org.jxmpp.stringprep.XmppStringprepException;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;

public class DatabaseBackend extends SQLiteOpenHelper
        implements eu.siacs.conversations.crypto.x3dhpq.X3dhpqDao {

    private static final String DATABASE_NAME = "history";
    private static final int DATABASE_VERSION = 65;

    // Column/table names for the legacy OMEMO tables, kept only so historical DB
    // migrations continue to work after the OMEMO code was removed.
    private static final String AXOLOTL_PREKEY_TABLENAME = "prekeys";
    private static final String AXOLOTL_SIGNED_PREKEY_TABLENAME = "signed_prekeys";
    private static final String AXOLOTL_SESSION_TABLENAME = "sessions";
    private static final String AXOLOTL_IDENTITIES_TABLENAME = "identities";
    private static final String AXOLOTL_ACCOUNT = "account";
    private static final String AXOLOTL_DEVICE_ID = "device_id";
    private static final String AXOLOTL_ID = "id";
    private static final String AXOLOTL_KEY = "key";
    private static final String AXOLOTL_NAME = "name";
    private static final String AXOLOTL_TRUSTED = "trusted";
    private static final String AXOLOTL_TRUST = "trust";
    private static final String AXOLOTL_ACTIVE = "active";
    private static final String AXOLOTL_LAST_ACTIVATION = "last_activation";
    private static final String AXOLOTL_OWN = "ownkey";
    private static final String AXOLOTL_FINGERPRINT = "fingerprint";
    private static final String AXOLOTL_CERTIFICATE = "certificate";
    private static final String AXOLOTL_JSONKEY_REGISTRATION_ID = "axolotl_reg_id";

    private static boolean requiresMessageIndexRebuild = false;
    private static DatabaseBackend instance = null;
    private static final String CREATE_CONTACTS_STATEMENT =
            "create table "
                    + Contact.TABLENAME
                    + "("
                    + Contact.ACCOUNT
                    + " TEXT, "
                    + Contact.SERVERNAME
                    + " TEXT, "
                    + Contact.SYSTEMNAME
                    + " TEXT,"
                    + Contact.PRESENCE_NAME
                    + " TEXT,"
                    + Contact.JID
                    + " TEXT,"
                    + Contact.KEYS
                    + " TEXT,"
                    + Contact.PHOTOURI
                    + " TEXT,"
                    + Contact.OPTIONS
                    + " NUMBER,"
                    + Contact.SYSTEMACCOUNT
                    + " NUMBER, "
                    + Contact.AVATAR
                    + " TEXT, "
                    + Contact.LAST_PRESENCE
                    + " TEXT, "
                    + Contact.LAST_TIME
                    + " NUMBER, "
                    + Contact.RTP_CAPABILITY
                    + " TEXT,"
                    + Contact.GROUPS
                    + " TEXT, FOREIGN KEY("
                    + Contact.ACCOUNT
                    + ") REFERENCES "
                    + Account.TABLENAME
                    + "("
                    + Account.UUID
                    + ") ON DELETE CASCADE, UNIQUE("
                    + Contact.ACCOUNT
                    + ", "
                    + Contact.JID
                    + ") ON CONFLICT REPLACE);";

    private static final String CREATE_PRESENCE_TEMPLATES_STATEMENT =
            "CREATE TABLE "
                    + PresenceTemplate.TABELNAME
                    + "("
                    + PresenceTemplate.UUID
                    + " TEXT, "
                    + PresenceTemplate.LAST_USED
                    + " NUMBER,"
                    + PresenceTemplate.MESSAGE
                    + " TEXT,"
                    + PresenceTemplate.STATUS
                    + " TEXT,"
                    + "UNIQUE("
                    + PresenceTemplate.MESSAGE
                    + ","
                    + PresenceTemplate.STATUS
                    + ") ON CONFLICT REPLACE);";

    private static final String CREATE_PREKEYS_STATEMENT =
            "CREATE TABLE "
                    + AXOLOTL_PREKEY_TABLENAME
                    + "("
                    + AXOLOTL_ACCOUNT
                    + " TEXT,  "
                    + AXOLOTL_ID
                    + " INTEGER, "
                    + AXOLOTL_KEY
                    + " TEXT, FOREIGN KEY("
                    + AXOLOTL_ACCOUNT
                    + ") REFERENCES "
                    + Account.TABLENAME
                    + "("
                    + Account.UUID
                    + ") ON DELETE CASCADE, "
                    + "UNIQUE( "
                    + AXOLOTL_ACCOUNT
                    + ", "
                    + AXOLOTL_ID
                    + ") ON CONFLICT REPLACE"
                    + ");";

    private static final String CREATE_SIGNED_PREKEYS_STATEMENT =
            "CREATE TABLE "
                    + AXOLOTL_SIGNED_PREKEY_TABLENAME
                    + "("
                    + AXOLOTL_ACCOUNT
                    + " TEXT,  "
                    + AXOLOTL_ID
                    + " INTEGER, "
                    + AXOLOTL_KEY
                    + " TEXT, FOREIGN KEY("
                    + AXOLOTL_ACCOUNT
                    + ") REFERENCES "
                    + Account.TABLENAME
                    + "("
                    + Account.UUID
                    + ") ON DELETE CASCADE, "
                    + "UNIQUE( "
                    + AXOLOTL_ACCOUNT
                    + ", "
                    + AXOLOTL_ID
                    + ") ON CONFLICT REPLACE"
                    + ");";

    private static final String CREATE_SESSIONS_STATEMENT =
            "CREATE TABLE "
                    + AXOLOTL_SESSION_TABLENAME
                    + "("
                    + AXOLOTL_ACCOUNT
                    + " TEXT,  "
                    + AXOLOTL_NAME
                    + " TEXT, "
                    + AXOLOTL_DEVICE_ID
                    + " INTEGER, "
                    + AXOLOTL_KEY
                    + " TEXT, FOREIGN KEY("
                    + AXOLOTL_ACCOUNT
                    + ") REFERENCES "
                    + Account.TABLENAME
                    + "("
                    + Account.UUID
                    + ") ON DELETE CASCADE, "
                    + "UNIQUE( "
                    + AXOLOTL_ACCOUNT
                    + ", "
                    + AXOLOTL_NAME
                    + ", "
                    + AXOLOTL_DEVICE_ID
                    + ") ON CONFLICT REPLACE"
                    + ");";

    private static final String CREATE_IDENTITIES_STATEMENT =
            "CREATE TABLE "
                    + AXOLOTL_IDENTITIES_TABLENAME
                    + "("
                    + AXOLOTL_ACCOUNT
                    + " TEXT,  "
                    + AXOLOTL_NAME
                    + " TEXT, "
                    + AXOLOTL_OWN
                    + " INTEGER, "
                    + AXOLOTL_FINGERPRINT
                    + " TEXT, "
                    + AXOLOTL_CERTIFICATE
                    + " BLOB, "
                    + AXOLOTL_TRUST
                    + " TEXT, "
                    + AXOLOTL_ACTIVE
                    + " NUMBER, "
                    + AXOLOTL_LAST_ACTIVATION
                    + " NUMBER,"
                    + AXOLOTL_KEY
                    + " TEXT, FOREIGN KEY("
                    + AXOLOTL_ACCOUNT
                    + ") REFERENCES "
                    + Account.TABLENAME
                    + "("
                    + Account.UUID
                    + ") ON DELETE CASCADE, "
                    + "UNIQUE( "
                    + AXOLOTL_ACCOUNT
                    + ", "
                    + AXOLOTL_NAME
                    + ", "
                    + AXOLOTL_FINGERPRINT
                    + ") ON CONFLICT IGNORE"
                    + ");";

    private static final String CREATE_CAPS_CACHE_TABLE =
            "CREATE TABLE caps_cache (caps TEXT, caps2 TEXT, disco_info TEXT, UNIQUE (caps), UNIQUE"
                    + " (caps2));";
    private static final String CREATE_CAPS_CACHE_INDEX_CAPS =
            "CREATE INDEX idx_caps ON caps_cache(caps);";
    private static final String CREATE_CAPS_CACHE_INDEX_CAPS2 =
            "CREATE INDEX idx_caps2 ON caps_cache(caps2);";

    // x3dhpq table creation statements (added in DATABASE_VERSION = 56)
    // Schema for x3dhpq tables (added in DATABASE_VERSION = 56).
    // Live migration tested under Wave D once instrumented test infrastructure is exercised.
    private static final String CREATE_X3DHPQ_ACCOUNT_IDENTITY =
            "CREATE TABLE IF NOT EXISTS x3dhpq_account_identity ("
                    + "account_uuid TEXT PRIMARY KEY NOT NULL,"
                    + "aik_priv_marshal BLOB NOT NULL,"   // AccountIdentityKey raw priv bytes
                    + "aik_pub_marshal BLOB NOT NULL,"    // AccountIdentityPub.marshal() — 1987 bytes
                    + "fingerprint TEXT NOT NULL"         // 30-char hex grouped 5+space, BLAKE2b-160
                    + ")";
    private static final String CREATE_X3DHPQ_LOCAL_DEVICE =
            "CREATE TABLE IF NOT EXISTS x3dhpq_local_device ("
                    + "account_uuid TEXT NOT NULL,"
                    + "device_id INTEGER NOT NULL,"
                    + "dik_priv_marshal BLOB NOT NULL,"   // DeviceIdentityKey raw priv bytes
                    + "dc_marshal BLOB NOT NULL,"         // DeviceCertificate.marshal()
                    + "created_at INTEGER NOT NULL,"
                    + "flags INTEGER NOT NULL DEFAULT 0,"
                    + "PRIMARY KEY (account_uuid, device_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_SIGNED_PRE_KEY =
            "CREATE TABLE IF NOT EXISTS x3dhpq_signed_pre_key ("
                    + "account_uuid TEXT NOT NULL,"
                    + "key_id INTEGER NOT NULL,"
                    + "public_x25519 BLOB NOT NULL,"      // 32 bytes
                    + "private_x25519 BLOB NOT NULL,"     // 32 bytes
                    + "signature_ed25519 BLOB NOT NULL,"  // 64 bytes
                    + "signature_mldsa BLOB NOT NULL,"    // 3309 bytes
                    + "created_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, key_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_KEM_PRE_KEY =
            "CREATE TABLE IF NOT EXISTS x3dhpq_kem_pre_key ("
                    + "account_uuid TEXT NOT NULL,"
                    + "key_id INTEGER NOT NULL,"
                    + "public_key BLOB NOT NULL,"         // ML-KEM-768 public, 1184 bytes
                    + "private_key BLOB NOT NULL,"        // ML-KEM-768 private encoded
                    + "sig_ed25519 BLOB NOT NULL,"        // DIK Ed25519 sig over public_key (spec §9.1)
                    + "sig_mldsa BLOB NOT NULL,"          // DIK ML-DSA-65 sig over public_key (spec §9.1)
                    + "PRIMARY KEY (account_uuid, key_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_ONE_TIME_PRE_KEY =
            "CREATE TABLE IF NOT EXISTS x3dhpq_one_time_pre_key ("
                    + "account_uuid TEXT NOT NULL,"
                    + "key_id INTEGER NOT NULL,"
                    + "public_x25519 BLOB NOT NULL,"      // 32 bytes
                    + "private_x25519 BLOB NOT NULL,"     // 32 bytes
                    + "consumed INTEGER NOT NULL DEFAULT 0,"
                    + "PRIMARY KEY (account_uuid, key_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_REMOTE_DEVICE =
            "CREATE TABLE IF NOT EXISTS x3dhpq_remote_device ("
                    + "account_uuid TEXT NOT NULL,"
                    + "peer_jid TEXT NOT NULL,"
                    + "device_id INTEGER NOT NULL,"
                    + "cert_marshal BLOB NOT NULL,"       // DeviceCertificate.marshal()
                    + "last_seen INTEGER,"
                    + "PRIMARY KEY (account_uuid, peer_jid, device_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_REMOTE_BUNDLE =
            "CREATE TABLE IF NOT EXISTS x3dhpq_remote_bundle ("
                    + "account_uuid TEXT NOT NULL,"
                    + "peer_jid TEXT NOT NULL,"
                    + "device_id INTEGER NOT NULL,"
                    + "aik_pub_marshal BLOB NOT NULL,"    // pinned AccountIdentityPub for the peer
                    + "bundle_xml BLOB NOT NULL,"         // raw XML of the published bundle
                    + "fetched_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, peer_jid, device_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_SESSION =
            "CREATE TABLE IF NOT EXISTS x3dhpq_session ("
                    + "account_uuid TEXT NOT NULL,"
                    + "peer_jid TEXT NOT NULL,"
                    + "device_id INTEGER NOT NULL,"
                    + "state_blob BLOB NOT NULL,"         // opaque Triple Ratchet state — Wave D defines format
                    + "updated_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, peer_jid, device_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_SESSION_PEER_INDEX =
            "CREATE INDEX x3dhpq_session_peer ON x3dhpq_session(account_uuid, peer_jid)";
    private static final String CREATE_X3DHPQ_AUDIT_ENTRY =
            "CREATE TABLE IF NOT EXISTS x3dhpq_audit_entry ("
                    + "account_uuid TEXT NOT NULL,"
                    + "owner_jid TEXT NOT NULL,"          // whose audit chain this is
                    + "seq INTEGER NOT NULL,"
                    + "prev_hash BLOB NOT NULL,"          // 32 bytes
                    + "action INTEGER NOT NULL,"
                    + "payload BLOB NOT NULL,"
                    + "timestamp INTEGER NOT NULL,"
                    + "sig_ed25519 BLOB NOT NULL,"
                    + "sig_mldsa BLOB NOT NULL,"
                    + "PRIMARY KEY (account_uuid, owner_jid, seq),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_AUDIT_OWNER_SEQ_INDEX =
            "CREATE INDEX x3dhpq_audit_owner_seq ON x3dhpq_audit_entry(account_uuid, owner_jid, seq)";
    private static final String CREATE_X3DHPQ_GROUP_SESSION =
            "CREATE TABLE IF NOT EXISTS x3dhpq_group_session ("
                    + "account_uuid TEXT NOT NULL,"
                    + "room_jid TEXT NOT NULL,"
                    + "epoch INTEGER NOT NULL,"
                    + "state_blob BLOB NOT NULL,"         // opaque GroupSession state — Wave E defines format
                    + "updated_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, room_jid),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";
    private static final String CREATE_X3DHPQ_GROUP_MEMBERSHIP =
            "CREATE TABLE IF NOT EXISTS x3dhpq_group_membership ("
                    + "account_uuid TEXT NOT NULL,"
                    + "room_jid TEXT NOT NULL,"
                    + "entry_hash TEXT NOT NULL,"         // hex(SHA-256(journal_blob))
                    + "journal_blob BLOB NOT NULL,"       // raw signed v1/v2 membership journal item
                    + "item_id TEXT NOT NULL,"
                    + "fetched_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, room_jid, entry_hash),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";

    // Per-account devicelist version + last-seen content state (§8.2, §8.5).
    // owner_jid is the account whose devicelist this row tracks: our own bare
    // JID for the publish-side monotonic counter, or a peer bare JID for the
    // receive-side rollback/fork/transitional gate. content_hash is SHA-256 of
    // the sorted device records (id|added_at|flags|cert) — the stable content
    // that excludes version and issued_at. accepted_signed flips to 1 once a
    // valid signed list has been accepted for the owner (downgrade lock, §8.5).
    private static final String CREATE_X3DHPQ_DEVICELIST_STATE =
            "CREATE TABLE IF NOT EXISTS x3dhpq_devicelist_state ("
                    + "account_uuid TEXT NOT NULL,"
                    + "owner_jid TEXT NOT NULL,"
                    + "version INTEGER NOT NULL,"
                    + "content_hash BLOB NOT NULL,"     // SHA-256 of sorted device records
                    + "accepted_signed INTEGER NOT NULL DEFAULT 0,"
                    + "updated_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, owner_jid),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";

    private static final String CREATE_X3DHPQ_PAIRING_SESSION =
            "CREATE TABLE IF NOT EXISTS x3dhpq_pairing_session ("
                    + "sid BLOB PRIMARY KEY NOT NULL,"
                    + "account_uuid TEXT NOT NULL,"
                    + "role INTEGER NOT NULL,"            // 0=existing/initiator, 1=new/responder
                    + "peer_jid TEXT NOT NULL,"
                    + "code TEXT NOT NULL,"               // 10-digit pairing code (with Luhn check)
                    + "state_blob BLOB,"                  // opaque CPace transcript + advancing state
                    + "expires_at INTEGER NOT NULL,"      // unix seconds; rows past this are sweepable
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + ")";
    private static final String CREATE_X3DHPQ_PAIRING_SESSION_EXPIRY_INDEX =
            "CREATE INDEX x3dhpq_pairing_session_expiry ON x3dhpq_pairing_session(expires_at)";

    // Co-account devices: OTHER physical devices under this account's AIK that this
    // install did not generate itself (e.g. enrolled via pairing while acting as the
    // existing/primary side). Holds only the public DeviceCertificate — never a
    // private key — so the devicelist publish path (§8.2) can union these with
    // x3dhpq_local_device to build the account's authoritative device set instead of
    // clobbering it with local-only devices (added in DATABASE_VERSION = 59).
    private static final String CREATE_X3DHPQ_CO_ACCOUNT_DEVICE =
            "CREATE TABLE IF NOT EXISTS x3dhpq_co_account_device ("
                    + "account_uuid TEXT NOT NULL,"
                    + "device_id INTEGER NOT NULL,"
                    + "dc_marshal BLOB NOT NULL,"          // DeviceCertificate.marshal(), issued by our AIK
                    + "added_at INTEGER NOT NULL,"
                    + "flags INTEGER NOT NULL DEFAULT 0,"
                    + "PRIMARY KEY (account_uuid, device_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";

    // Committed device-id set: the device ids of the most recently ACCEPTED (inbound,
    // own list) or PUBLISHED (outbound) authoritative devicelist for the account.
    // Deliberately independent of x3dhpq_local_device / x3dhpq_co_account_device
    // (the volatile tables used to BUILD the outbound list) so publishDeviceList()
    // can compare "what we are about to publish" against "what was last known
    // authoritative" without the comparison being circular. Used to refuse a
    // publish that silently drops a previously-known device without an explicit
    // §8.6 revocation (added in DATABASE_VERSION = 60).
    private static final String CREATE_X3DHPQ_COMMITTED_DEVICE =
            "CREATE TABLE IF NOT EXISTS x3dhpq_committed_device ("
                    + "account_uuid TEXT NOT NULL,"
                    + "device_id INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, device_id),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";

    // Device-audit DAG entries (x3dhpq-xep-draft.md §11.7): the multi-writer
    // device-authorization ratchet log folded by DeviceDag/DeviceAuditEntryV2
    // (libs/x3dhpq-core) to derive the account's authorized device set. entry_blob
    // is the opaque DeviceAuditEntryV2.marshal() bytes; entry_hash_hex is
    // hex(SHA-256(marshal())), used both as the ingest dedup key and as a parent
    // reference for later entries.
    //
    // SCHEMA SAFETY: this table intentionally has NO foreign key to
    // x3dhpq_account_identity. A pending-enrollment device already has an AIK row
    // (see LocalKeyBootstrap#ensureBootstrapped's FK-crash fix), but genesis-import
    // ordering here must not be able to reproduce that class of bug — so the only
    // FK is to accounts(uuid), which is always satisfied (the row is created by
    // account bind, long before any x3dhpq state exists). Added in DATABASE_VERSION
    // = 61.
    private static final String CREATE_X3DHPQ_DEVICE_AUDIT =
            "CREATE TABLE IF NOT EXISTS x3dhpq_device_audit ("
                    + "account_uuid TEXT NOT NULL,"
                    + "entry_hash_hex TEXT NOT NULL,"
                    + "entry_blob BLOB NOT NULL,"
                    + "created_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, entry_hash_hex),"
                    + "FOREIGN KEY (account_uuid) REFERENCES "
                    + Account.TABLENAME + "(" + Account.UUID + ")"
                    + " ON DELETE CASCADE"
                    + ")";

    // Trust Manifest Phase 2 per-owner rollback/fork guard state (contract §C.3): the
    // last accepted TrustManifest version for an owner (own bare JID or a contact), the
    // SHA-256 of its marshalled blob, and the blob itself (so a same-version republish
    // can be checked for equivocation/fork). One row per (account, owner). Added in
    // DATABASE_VERSION = 62.
    private static final String CREATE_X3DHPQ_MANIFEST_STATE =
            "CREATE TABLE IF NOT EXISTS x3dhpq_manifest_state ("
                    + "account_uuid TEXT NOT NULL,"
                    + "owner_jid TEXT NOT NULL,"
                    + "version INTEGER NOT NULL,"
                    + "blob_hash BLOB NOT NULL,"        // SHA-256(TrustManifest.marshal())
                    + "blob BLOB NOT NULL,"             // TrustManifest.marshal() of the accepted version
                    + "updated_at INTEGER NOT NULL,"
                    + "PRIMARY KEY (account_uuid, owner_jid),"
                    + "FOREIGN KEY (account_uuid) REFERENCES x3dhpq_account_identity(account_uuid)"
                    + " ON DELETE CASCADE"
                    + ")";

    private static final String RESOLVER_RESULTS_TABLENAME = "resolver_results";

    private static final String CREATE_RESOLVER_RESULTS_TABLE =
            "create table "
                    + RESOLVER_RESULTS_TABLENAME
                    + "("
                    + Resolver.Result.DOMAIN
                    + " TEXT,"
                    + Resolver.Result.HOSTNAME
                    + " TEXT,"
                    + Resolver.Result.IP
                    + " BLOB,"
                    + Resolver.Result.PRIORITY
                    + " NUMBER,"
                    + Resolver.Result.DIRECT_TLS
                    + " NUMBER,"
                    + Resolver.Result.AUTHENTICATED
                    + " NUMBER,"
                    + Resolver.Result.PORT
                    + " NUMBER,"
                    + "UNIQUE("
                    + Resolver.Result.DOMAIN
                    + ") ON CONFLICT REPLACE"
                    + ");";

    private static final String CREATE_MESSAGE_TIME_INDEX =
            "CREATE INDEX message_time_index ON "
                    + Message.TABLENAME
                    + "("
                    + Message.TIME_SENT
                    + ")";
    private static final String CREATE_MESSAGE_CONVERSATION_INDEX =
            "CREATE INDEX message_conversation_index ON "
                    + Message.TABLENAME
                    + "("
                    + Message.CONVERSATION
                    + ")";
    private static final String CREATE_MESSAGE_DELETED_INDEX =
            "CREATE INDEX message_deleted_index ON "
                    + Message.TABLENAME
                    + "("
                    + Message.DELETED
                    + ")";
    private static final String CREATE_MESSAGE_RELATIVE_FILE_PATH_INDEX =
            "CREATE INDEX message_file_path_index ON "
                    + Message.TABLENAME
                    + "("
                    + Message.RELATIVE_FILE_PATH
                    + ")";
    private static final String CREATE_MESSAGE_TYPE_INDEX =
            "CREATE INDEX message_type_index ON " + Message.TABLENAME + "(" + Message.TYPE + ")";

    private static final String CREATE_MESSAGE_INDEX_TABLE =
            "CREATE VIRTUAL TABLE messages_index USING fts4"
                    + " (uuid,body,notindexed=\"uuid\",content=\""
                    + Message.TABLENAME
                    + "\",tokenize='unicode61')";
    private static final String CREATE_MESSAGE_INSERT_TRIGGER =
            "CREATE TRIGGER after_message_insert AFTER INSERT ON "
                    + Message.TABLENAME
                    + " BEGIN INSERT INTO messages_index(rowid,uuid,body)"
                    + " VALUES(NEW.rowid,NEW.uuid,NEW.body); END;";
    private static final String CREATE_MESSAGE_UPDATE_TRIGGER =
            "CREATE TRIGGER after_message_update UPDATE OF uuid,body ON "
                    + Message.TABLENAME
                    + " BEGIN UPDATE messages_index SET body=NEW.body,uuid=NEW.uuid WHERE"
                    + " rowid=OLD.rowid; END;";
    private static final String CREATE_MESSAGE_DELETE_TRIGGER =
            "CREATE TRIGGER after_message_delete AFTER DELETE ON "
                    + Message.TABLENAME
                    + " BEGIN DELETE FROM messages_index WHERE rowid=OLD.rowid; END;";
    private static final String COPY_PREEXISTING_ENTRIES =
            "INSERT INTO messages_index(messages_index) VALUES('rebuild');";

    private final Context context;

    private DatabaseBackend(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
        this.context = context.getApplicationContext();
    }

    private static ContentValues createFingerprintStatusContentValues(
            String trust, boolean active) {
        ContentValues values = new ContentValues();
        values.put(AXOLOTL_TRUST, trust);
        values.put(AXOLOTL_ACTIVE, active ? 1 : 0);
        return values;
    }

    public static boolean requiresMessageIndexRebuild() {
        return requiresMessageIndexRebuild;
    }

    public void rebuildMessagesIndex() {
        final SQLiteDatabase db = getWritableDatabase();
        final Stopwatch stopwatch = Stopwatch.createStarted();
        db.execSQL(COPY_PREEXISTING_ENTRIES);
        Log.d(Config.LOGTAG, "rebuilt message index in " + stopwatch.stop());
    }

    public static synchronized DatabaseBackend getInstance(Context context) {
        if (instance == null) {
            instance = new DatabaseBackend(context);
        }
        return instance;
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        db.execSQL("PRAGMA foreign_keys=ON");
        db.rawQuery("PRAGMA secure_delete=ON", null).close();
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(
                "create table "
                        + Account.TABLENAME
                        + "("
                        + Account.UUID
                        + " TEXT PRIMARY KEY,"
                        + Account.USERNAME
                        + " TEXT,"
                        + Account.SERVER
                        + " TEXT,"
                        + Account.PASSWORD
                        + " TEXT,"
                        + Account.DISPLAY_NAME
                        + " TEXT, "
                        + Account.STATUS
                        + " TEXT,"
                        + Account.STATUS_MESSAGE
                        + " TEXT,"
                        + Account.ROSTERVERSION
                        + " TEXT,"
                        + Account.OPTIONS
                        + " NUMBER, "
                        + Account.AVATAR
                        + " TEXT, "
                        + Account.KEYS
                        + " TEXT, "
                        + Account.HOSTNAME
                        + " TEXT, "
                        + Account.RESOURCE
                        + " TEXT,"
                        + Account.PINNED_MECHANISM
                        + " TEXT,"
                        + Account.PINNED_CHANNEL_BINDING
                        + " TEXT,"
                        + Account.FAST_MECHANISM
                        + " TEXT,"
                        + Account.FAST_TOKEN
                        + " TEXT,"
                        + Account.PORT
                        + " NUMBER DEFAULT 5222)");
        db.execSQL(
                "create table "
                        + Conversation.TABLENAME
                        + " ("
                        + Conversation.UUID
                        + " TEXT PRIMARY KEY, "
                        + Conversation.NAME
                        + " TEXT, "
                        + Conversation.CONTACT
                        + " TEXT, "
                        + Conversation.ACCOUNT
                        + " TEXT, "
                        + Conversation.CONTACTJID
                        + " TEXT, "
                        + Conversation.CREATED
                        + " NUMBER, "
                        + Conversation.STATUS
                        + " NUMBER, "
                        + Conversation.MODE
                        + " NUMBER, "
                        + Conversation.ATTRIBUTES
                        + " TEXT, FOREIGN KEY("
                        + Conversation.ACCOUNT
                        + ") REFERENCES "
                        + Account.TABLENAME
                        + "("
                        + Account.UUID
                        + ") ON DELETE CASCADE);");
        db.execSQL(
                "create table "
                        + Message.TABLENAME
                        + "( "
                        + Message.UUID
                        + " TEXT PRIMARY KEY, "
                        + Message.CONVERSATION
                        + " TEXT, "
                        + Message.TIME_SENT
                        + " NUMBER, "
                        + Message.COUNTERPART
                        + " TEXT, "
                        + Message.TRUE_COUNTERPART
                        + " TEXT,"
                        + Message.BODY
                        + " TEXT, "
                        + Message.ENCRYPTION
                        + " NUMBER, "
                        + Message.STATUS
                        + " NUMBER,"
                        + Message.TYPE
                        + " NUMBER, "
                        + Message.RELATIVE_FILE_PATH
                        + " TEXT, "
                        + Message.SHARED_STORAGE
                        + " BOOLEAN NOT NULL DEFAULT 1,"
                        + Message.SERVER_MSG_ID
                        + " TEXT, "
                        + Message.FINGERPRINT
                        + " TEXT, "
                        + Message.CARBON
                        + " INTEGER, "
                        + Message.EDITED
                        + " TEXT, "
                        + Message.READ
                        + " NUMBER DEFAULT 1, "
                        + Message.OOB
                        + " INTEGER, "
                        + Message.ERROR_MESSAGE
                        + " TEXT,"
                        + Message.READ_BY_MARKERS
                        + " TEXT,"
                        + Message.MARKABLE
                        + " NUMBER DEFAULT 0,"
                        + Message.DELETED
                        + " NUMBER DEFAULT 0,"
                        + Message.BODY_LANGUAGE
                        + " TEXT,"
                        + Message.OCCUPANT_ID
                        + " TEXT,"
                        + Message.REACTIONS
                        + " TEXT,"
                        + Message.X3DHPQ_SOURCE_DEVICE
                        + " INTEGER,"
                        + Message.REMOTE_MSG_ID
                        + " TEXT, FOREIGN KEY("
                        + Message.CONVERSATION
                        + ") REFERENCES "
                        + Conversation.TABLENAME
                        + "("
                        + Conversation.UUID
                        + ") ON DELETE CASCADE);");
        db.execSQL(CREATE_MESSAGE_TIME_INDEX);
        db.execSQL(CREATE_MESSAGE_CONVERSATION_INDEX);
        db.execSQL(CREATE_MESSAGE_DELETED_INDEX);
        db.execSQL(CREATE_MESSAGE_RELATIVE_FILE_PATH_INDEX);
        db.execSQL(CREATE_MESSAGE_TYPE_INDEX);
        db.execSQL(CREATE_CONTACTS_STATEMENT);
        db.execSQL(CREATE_SESSIONS_STATEMENT);
        db.execSQL(CREATE_PREKEYS_STATEMENT);
        db.execSQL(CREATE_SIGNED_PREKEYS_STATEMENT);
        db.execSQL(CREATE_IDENTITIES_STATEMENT);
        db.execSQL(CREATE_PRESENCE_TEMPLATES_STATEMENT);
        db.execSQL(CREATE_RESOLVER_RESULTS_TABLE);
        db.execSQL(CREATE_MESSAGE_INDEX_TABLE);
        db.execSQL(CREATE_MESSAGE_INSERT_TRIGGER);
        db.execSQL(CREATE_MESSAGE_UPDATE_TRIGGER);
        db.execSQL(CREATE_MESSAGE_DELETE_TRIGGER);
        db.execSQL(CREATE_CAPS_CACHE_TABLE);
        db.execSQL(CREATE_CAPS_CACHE_INDEX_CAPS);
        db.execSQL(CREATE_CAPS_CACHE_INDEX_CAPS2);
        // x3dhpq tables for post-quantum key exchange state
        db.execSQL(CREATE_X3DHPQ_ACCOUNT_IDENTITY);
        db.execSQL(CREATE_X3DHPQ_LOCAL_DEVICE);
        db.execSQL(CREATE_X3DHPQ_SIGNED_PRE_KEY);
        db.execSQL(CREATE_X3DHPQ_KEM_PRE_KEY);
        db.execSQL(CREATE_X3DHPQ_ONE_TIME_PRE_KEY);
        db.execSQL(CREATE_X3DHPQ_REMOTE_DEVICE);
        db.execSQL(CREATE_X3DHPQ_REMOTE_BUNDLE);
        db.execSQL(CREATE_X3DHPQ_SESSION);
        db.execSQL(CREATE_X3DHPQ_SESSION_PEER_INDEX);
        db.execSQL(CREATE_X3DHPQ_AUDIT_ENTRY);
        db.execSQL(CREATE_X3DHPQ_AUDIT_OWNER_SEQ_INDEX);
        db.execSQL(CREATE_X3DHPQ_GROUP_SESSION);
        db.execSQL(CREATE_X3DHPQ_GROUP_MEMBERSHIP);
        db.execSQL(CREATE_X3DHPQ_DEVICELIST_STATE);
        db.execSQL(CREATE_X3DHPQ_PAIRING_SESSION);
        db.execSQL(CREATE_X3DHPQ_PAIRING_SESSION_EXPIRY_INDEX);
        db.execSQL(CREATE_X3DHPQ_CO_ACCOUNT_DEVICE);
        db.execSQL(CREATE_X3DHPQ_COMMITTED_DEVICE);
        db.execSQL(CREATE_X3DHPQ_DEVICE_AUDIT);
        db.execSQL(CREATE_X3DHPQ_MANIFEST_STATE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 2 && newVersion >= 2) {
            db.execSQL(
                    "update "
                            + Account.TABLENAME
                            + " set "
                            + Account.OPTIONS
                            + " = "
                            + Account.OPTIONS
                            + " | 8");
        }
        if (oldVersion < 3 && newVersion >= 3) {
            db.execSQL(
                    "ALTER TABLE " + Message.TABLENAME + " ADD COLUMN " + Message.TYPE + " NUMBER");
        }
        if (oldVersion < 5 && newVersion >= 5) {
            db.execSQL("DROP TABLE " + Contact.TABLENAME);
            db.execSQL(CREATE_CONTACTS_STATEMENT);
            db.execSQL("UPDATE " + Account.TABLENAME + " SET " + Account.ROSTERVERSION + " = NULL");
        }
        if (oldVersion < 6 && newVersion >= 6) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.TRUE_COUNTERPART
                            + " TEXT");
        }
        if (oldVersion < 7 && newVersion >= 7) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.REMOTE_MSG_ID
                            + " TEXT");
            db.execSQL(
                    "ALTER TABLE " + Contact.TABLENAME + " ADD COLUMN " + Contact.AVATAR + " TEXT");
            db.execSQL(
                    "ALTER TABLE " + Account.TABLENAME + " ADD COLUMN " + Account.AVATAR + " TEXT");
        }
        if (oldVersion < 8 && newVersion >= 8) {
            db.execSQL(
                    "ALTER TABLE "
                            + Conversation.TABLENAME
                            + " ADD COLUMN "
                            + Conversation.ATTRIBUTES
                            + " TEXT");
        }
        if (oldVersion < 9 && newVersion >= 9) {
            db.execSQL(
                    "ALTER TABLE "
                            + Contact.TABLENAME
                            + " ADD COLUMN "
                            + Contact.LAST_TIME
                            + " NUMBER");
            db.execSQL(
                    "ALTER TABLE "
                            + Contact.TABLENAME
                            + " ADD COLUMN "
                            + Contact.LAST_PRESENCE
                            + " TEXT");
        }
        if (oldVersion < 10 && newVersion >= 10) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.RELATIVE_FILE_PATH
                            + " TEXT");
        }
        if (oldVersion < 11 && newVersion >= 11) {
            db.execSQL(
                    "ALTER TABLE " + Contact.TABLENAME + " ADD COLUMN " + Contact.GROUPS + " TEXT");
            db.execSQL("delete from " + Contact.TABLENAME);
            db.execSQL("update " + Account.TABLENAME + " set " + Account.ROSTERVERSION + " = NULL");
        }
        if (oldVersion < 12 && newVersion >= 12) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.SERVER_MSG_ID
                            + " TEXT");
        }
        if (oldVersion < 13 && newVersion >= 13) {
            db.execSQL("delete from " + Contact.TABLENAME);
            db.execSQL("update " + Account.TABLENAME + " set " + Account.ROSTERVERSION + " = NULL");
        }
        if (oldVersion < 14 && newVersion >= 14) {
            canonicalizeJids(db);
        }
        if (oldVersion < 15 && newVersion >= 15) {
            recreateAxolotlDb(db);
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.FINGERPRINT
                            + " TEXT");
        }
        if (oldVersion < 16 && newVersion >= 16) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.CARBON
                            + " INTEGER");
        }
        if (oldVersion < 19 && newVersion >= 19) {
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.DISPLAY_NAME
                            + " TEXT");
        }
        if (oldVersion < 20 && newVersion >= 20) {
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.HOSTNAME
                            + " TEXT");
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.PORT
                            + " NUMBER DEFAULT 5222");
        }
        if (oldVersion < 26 && newVersion >= 26) {
            db.execSQL(
                    "ALTER TABLE " + Account.TABLENAME + " ADD COLUMN " + Account.STATUS + " TEXT");
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.STATUS_MESSAGE
                            + " TEXT");
        }
        if (oldVersion < 40 && newVersion >= 40) {
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.RESOURCE
                            + " TEXT");
        }
        /* Any migrations that alter the Account table need to happen BEFORE this migration, as it
         * depends on account de-serialization.
         */
        if (oldVersion < 17 && newVersion >= 17 && newVersion < 31) {
            List<Account> accounts = getAccounts(db);
            for (Account account : accounts) {
                String ownDeviceIdString =
                        account.getKey(AXOLOTL_JSONKEY_REGISTRATION_ID);
                if (ownDeviceIdString == null) {
                    continue;
                }
                int ownDeviceId = Integer.valueOf(ownDeviceIdString);
                SignalProtocolAddress ownAddress =
                        new SignalProtocolAddress(
                                account.getJid().asBareJid().toString(), ownDeviceId);
                deleteSession(db, account, ownAddress);
                IdentityKeyPair identityKeyPair = loadOwnIdentityKeyPair(db, account);
                if (identityKeyPair != null) {
                    String[] selectionArgs = {
                        account.getUuid(),
                        CryptoHelper.bytesToHex(identityKeyPair.getPublicKey().serialize())
                    };
                    ContentValues values = new ContentValues();
                    values.put(AXOLOTL_TRUSTED, 2);
                    db.update(
                            AXOLOTL_IDENTITIES_TABLENAME,
                            values,
                            AXOLOTL_ACCOUNT
                                    + " = ? AND "
                                    + AXOLOTL_FINGERPRINT
                                    + " = ? ",
                            selectionArgs);
                } else {
                    Log.d(
                            Config.LOGTAG,
                            account.getJid().asBareJid()
                                    + ": could not load own identity key pair");
                }
            }
        }
        if (oldVersion < 18 && newVersion >= 18) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.READ
                            + " NUMBER DEFAULT 1");
        }

        if (oldVersion < 21 && newVersion >= 21) {
            List<Account> accounts = getAccounts(db);
            for (Account account : accounts) {
                account.unsetPgpSignature();
                db.update(
                        Account.TABLENAME,
                        account.getContentValues(),
                        Account.UUID + "=?",
                        new String[] {account.getUuid()});
            }
        }

        if (oldVersion >= 15 && oldVersion < 22 && newVersion >= 22) {
            db.execSQL(
                    "ALTER TABLE "
                            + AXOLOTL_IDENTITIES_TABLENAME
                            + " ADD COLUMN "
                            + AXOLOTL_CERTIFICATE);
        }

        if (oldVersion < 24 && newVersion >= 24) {
            db.execSQL(
                    "ALTER TABLE " + Message.TABLENAME + " ADD COLUMN " + Message.EDITED + " TEXT");
        }

        if (oldVersion < 25 && newVersion >= 25) {
            db.execSQL(
                    "ALTER TABLE " + Message.TABLENAME + " ADD COLUMN " + Message.OOB + " INTEGER");
        }

        if (oldVersion < 26 && newVersion >= 26) {
            db.execSQL(CREATE_PRESENCE_TEMPLATES_STATEMENT);
        }

        if (oldVersion < 28 && newVersion >= 28) {
            canonicalizeJids(db);
        }

        if (oldVersion < 29 && newVersion >= 29) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.ERROR_MESSAGE
                            + " TEXT");
        }
        if (oldVersion >= 15 && oldVersion < 31 && newVersion >= 31) {
            db.execSQL(
                    "ALTER TABLE "
                            + AXOLOTL_IDENTITIES_TABLENAME
                            + " ADD COLUMN "
                            + AXOLOTL_TRUST
                            + " TEXT");
            db.execSQL(
                    "ALTER TABLE "
                            + AXOLOTL_IDENTITIES_TABLENAME
                            + " ADD COLUMN "
                            + AXOLOTL_ACTIVE
                            + " NUMBER");
            HashMap<Integer, ContentValues> migration = new HashMap<>();
            migration.put(
                    0, createFingerprintStatusContentValues("TRUSTED", true));
            migration.put(
                    1, createFingerprintStatusContentValues("TRUSTED", true));
            migration.put(
                    2,
                    createFingerprintStatusContentValues("UNTRUSTED", true));
            migration.put(
                    3,
                    createFingerprintStatusContentValues(
                            "COMPROMISED", false));
            migration.put(
                    4,
                    createFingerprintStatusContentValues("TRUSTED", false));
            migration.put(
                    5,
                    createFingerprintStatusContentValues("TRUSTED", false));
            migration.put(
                    6,
                    createFingerprintStatusContentValues("UNTRUSTED", false));
            migration.put(
                    7,
                    createFingerprintStatusContentValues(
                            "VERIFIED_X509", true));
            migration.put(
                    8,
                    createFingerprintStatusContentValues(
                            "VERIFIED_X509", false));
            for (Map.Entry<Integer, ContentValues> entry : migration.entrySet()) {
                String whereClause = AXOLOTL_TRUSTED + "=?";
                String[] where = {String.valueOf(entry.getKey())};
                db.update(
                        AXOLOTL_IDENTITIES_TABLENAME,
                        entry.getValue(),
                        whereClause,
                        where);
            }
        }
        if (oldVersion >= 15 && oldVersion < 32 && newVersion >= 32) {
            db.execSQL(
                    "ALTER TABLE "
                            + AXOLOTL_IDENTITIES_TABLENAME
                            + " ADD COLUMN "
                            + AXOLOTL_LAST_ACTIVATION
                            + " NUMBER");
            ContentValues defaults = new ContentValues();
            defaults.put(AXOLOTL_LAST_ACTIVATION, System.currentTimeMillis());
            db.update(AXOLOTL_IDENTITIES_TABLENAME, defaults, null, null);
        }
        if (oldVersion >= 15 && oldVersion < 33 && newVersion >= 33) {
            String whereClause = AXOLOTL_OWN + "=1";
            db.update(
                    AXOLOTL_IDENTITIES_TABLENAME,
                    createFingerprintStatusContentValues("VERIFIED", true),
                    whereClause,
                    null);
        }

        if (oldVersion < 34 && newVersion >= 34) {
            db.execSQL(CREATE_MESSAGE_TIME_INDEX);

            final File oldPicturesDirectory =
                    new File(
                            Environment.getExternalStoragePublicDirectory(
                                            Environment.DIRECTORY_PICTURES)
                                    + "/Conversations/");
            final File oldFilesDirectory =
                    new File(Environment.getExternalStorageDirectory() + "/Conversations/");
            final File newFilesDirectory =
                    new File(
                            Environment.getExternalStorageDirectory()
                                    + "/Conversations/Media/Conversations Files/");
            final File newVideosDirectory =
                    new File(
                            Environment.getExternalStorageDirectory()
                                    + "/Conversations/Media/Conversations Videos/");
            if (oldPicturesDirectory.exists() && oldPicturesDirectory.isDirectory()) {
                final File newPicturesDirectory =
                        new File(
                                Environment.getExternalStorageDirectory()
                                        + "/Conversations/Media/Conversations Images/");
                newPicturesDirectory.getParentFile().mkdirs();
                if (oldPicturesDirectory.renameTo(newPicturesDirectory)) {
                    Log.d(
                            Config.LOGTAG,
                            "moved "
                                    + oldPicturesDirectory.getAbsolutePath()
                                    + " to "
                                    + newPicturesDirectory.getAbsolutePath());
                }
            }
            if (oldFilesDirectory.exists() && oldFilesDirectory.isDirectory()) {
                newFilesDirectory.mkdirs();
                newVideosDirectory.mkdirs();
                final File[] files = oldFilesDirectory.listFiles();
                if (files == null) {
                    return;
                }
                for (File file : files) {
                    if (file.getName().equals(".nomedia")) {
                        if (file.delete()) {
                            Log.d(
                                    Config.LOGTAG,
                                    "deleted nomedia file in "
                                            + oldFilesDirectory.getAbsolutePath());
                        }
                    } else if (file.isFile()) {
                        final String name = file.getName();
                        boolean isVideo = false;
                        int start = name.lastIndexOf('.') + 1;
                        if (start < name.length()) {
                            String mime =
                                    MimeUtils.guessMimeTypeFromExtension(name.substring(start));
                            isVideo = mime != null && mime.startsWith("video/");
                        }
                        File dst =
                                new File(
                                        (isVideo ? newVideosDirectory : newFilesDirectory)
                                                        .getAbsolutePath()
                                                + "/"
                                                + file.getName());
                        if (file.renameTo(dst)) {
                            Log.d(Config.LOGTAG, "moved " + file + " to " + dst);
                        }
                    }
                }
            }
        }
        if (oldVersion < 35 && newVersion >= 35) {
            db.execSQL(CREATE_MESSAGE_CONVERSATION_INDEX);
        }
        if (oldVersion < 36 && newVersion >= 36) {
            List<Account> accounts = getAccounts(db);
            for (Account account : accounts) {
                account.setOption(Account.OPTION_REQUIRES_ACCESS_MODE_CHANGE, true);
                account.setOption(Account.OPTION_LOGGED_IN_SUCCESSFULLY, false);
                db.update(
                        Account.TABLENAME,
                        account.getContentValues(),
                        Account.UUID + "=?",
                        new String[] {account.getUuid()});
            }
        }

        if (oldVersion < 37 && newVersion >= 37) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.READ_BY_MARKERS
                            + " TEXT");
        }

        if (oldVersion < 38 && newVersion >= 38) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.MARKABLE
                            + " NUMBER DEFAULT 0");
        }

        if (oldVersion < 39 && newVersion >= 39) {
            db.execSQL(CREATE_RESOLVER_RESULTS_TABLE);
        }

        if (QuickConversationsService.isQuicksy() && oldVersion < 43 && newVersion >= 43) {
            List<Account> accounts = getAccounts(db);
            for (Account account : accounts) {
                account.setOption(Account.OPTION_MAGIC_CREATE, true);
                db.update(
                        Account.TABLENAME,
                        account.getContentValues(),
                        Account.UUID + "=?",
                        new String[] {account.getUuid()});
            }
        }

        if (oldVersion < 44 && newVersion >= 44) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.DELETED
                            + " NUMBER DEFAULT 0");
            db.execSQL(CREATE_MESSAGE_DELETED_INDEX);
            db.execSQL(CREATE_MESSAGE_RELATIVE_FILE_PATH_INDEX);
            db.execSQL(CREATE_MESSAGE_TYPE_INDEX);
        }

        if (oldVersion < 45 && newVersion >= 45) {
            db.execSQL("ALTER TABLE " + Message.TABLENAME + " ADD COLUMN " + Message.BODY_LANGUAGE);
        }

        if (oldVersion < 46 && newVersion >= 46) {
            final long start = SystemClock.elapsedRealtime();
            db.rawQuery("PRAGMA secure_delete = FALSE", null).close();
            db.execSQL("update " + Message.TABLENAME + " set " + Message.EDITED + "=NULL");
            db.rawQuery("PRAGMA secure_delete=ON", null).close();
            final long diff = SystemClock.elapsedRealtime() - start;
            Log.d(Config.LOGTAG, "deleted old edit information in " + diff + "ms");
        }
        if (oldVersion < 47 && newVersion >= 47) {
            db.execSQL(
                    "ALTER TABLE "
                            + Contact.TABLENAME
                            + " ADD COLUMN "
                            + Contact.PRESENCE_NAME
                            + " TEXT");
        }
        if (oldVersion < 48 && newVersion >= 48) {
            db.execSQL(
                    "ALTER TABLE "
                            + Contact.TABLENAME
                            + " ADD COLUMN "
                            + Contact.RTP_CAPABILITY
                            + " TEXT");
        }
        if (oldVersion < 49 && newVersion >= 49) {
            db.beginTransaction();
            db.execSQL("DROP TRIGGER IF EXISTS after_message_insert;");
            db.execSQL("DROP TRIGGER IF EXISTS after_message_update;");
            db.execSQL("DROP TRIGGER IF EXISTS after_message_delete;");
            db.execSQL("DROP TABLE IF EXISTS messages_index;");
            // a hack that should not be necessary, but
            // there was at least one occurence when SQLite failed at this
            db.execSQL("DROP TABLE IF EXISTS messages_index_docsize;");
            db.execSQL("DROP TABLE IF EXISTS messages_index_segdir;");
            db.execSQL("DROP TABLE IF EXISTS messages_index_segments;");
            db.execSQL("DROP TABLE IF EXISTS messages_index_stat;");
            db.execSQL(CREATE_MESSAGE_INDEX_TABLE);
            db.execSQL(CREATE_MESSAGE_INSERT_TRIGGER);
            db.execSQL(CREATE_MESSAGE_UPDATE_TRIGGER);
            db.execSQL(CREATE_MESSAGE_DELETE_TRIGGER);
            db.setTransactionSuccessful();
            db.endTransaction();
            requiresMessageIndexRebuild = true;
        }
        if (oldVersion < 50 && newVersion >= 50) {
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.PINNED_MECHANISM
                            + " TEXT");
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.PINNED_CHANNEL_BINDING
                            + " TEXT");
        }
        if (oldVersion < 51 && newVersion >= 51) {
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.FAST_MECHANISM
                            + " TEXT");
            db.execSQL(
                    "ALTER TABLE "
                            + Account.TABLENAME
                            + " ADD COLUMN "
                            + Account.FAST_TOKEN
                            + " TEXT");
        }
        if (oldVersion < 52 && newVersion >= 52) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.OCCUPANT_ID
                            + " TEXT");
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.REACTIONS
                            + " TEXT");
        }
        if (oldVersion < 53 && newVersion >= 53) {
            try (final Cursor cursor =
                    db.query(
                            Account.TABLENAME,
                            new String[] {Account.UUID, Account.USERNAME},
                            null,
                            null,
                            null,
                            null,
                            null)) {
                while (cursor != null && cursor.moveToNext()) {
                    final var uuid = cursor.getString(0);
                    final var username = cursor.getString(1);
                    final Localpart localpart;
                    try {
                        localpart = Localpart.fromUnescaped(username);
                    } catch (final XmppStringprepException e) {
                        Log.d(Config.LOGTAG, "unable to parse jid");
                        continue;
                    }
                    final var contentValues = new ContentValues();
                    contentValues.putNull(Account.ROSTERVERSION);
                    contentValues.put(Account.USERNAME, localpart.toString());
                    db.update(
                            Account.TABLENAME,
                            contentValues,
                            Account.UUID + "=?",
                            new String[] {uuid});
                }
            }
        }
        if (oldVersion < 54 && newVersion >= 54) {
            db.execSQL("DROP TABLE discovery_results");
            db.execSQL(CREATE_CAPS_CACHE_TABLE);
            db.execSQL(CREATE_CAPS_CACHE_INDEX_CAPS);
            db.execSQL(CREATE_CAPS_CACHE_INDEX_CAPS2);
        }
        if (oldVersion < 55 && newVersion >= 55) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.SHARED_STORAGE
                            + " BOOLEAN NOT NULL DEFAULT 1");
        }
        // Schema for x3dhpq tables (added in DATABASE_VERSION = 56).
        // Live migration tested under Wave D once instrumented test infrastructure is exercised.
        if (oldVersion < 56 && newVersion >= 56) {
            db.execSQL(CREATE_X3DHPQ_ACCOUNT_IDENTITY);
            db.execSQL(CREATE_X3DHPQ_LOCAL_DEVICE);
            db.execSQL(CREATE_X3DHPQ_SIGNED_PRE_KEY);
            db.execSQL(CREATE_X3DHPQ_KEM_PRE_KEY);
            db.execSQL(CREATE_X3DHPQ_ONE_TIME_PRE_KEY);
            db.execSQL(CREATE_X3DHPQ_REMOTE_DEVICE);
            db.execSQL(CREATE_X3DHPQ_REMOTE_BUNDLE);
            db.execSQL(CREATE_X3DHPQ_SESSION);
            db.execSQL(CREATE_X3DHPQ_SESSION_PEER_INDEX);
            db.execSQL(CREATE_X3DHPQ_AUDIT_ENTRY);
            db.execSQL(CREATE_X3DHPQ_AUDIT_OWNER_SEQ_INDEX);
            db.execSQL(CREATE_X3DHPQ_GROUP_SESSION);
            db.execSQL(CREATE_X3DHPQ_GROUP_MEMBERSHIP);
        }
        // x3dhpq_pairing_session table (added in DATABASE_VERSION = 57).
        if (oldVersion < 57 && newVersion >= 57) {
            db.execSQL(CREATE_X3DHPQ_PAIRING_SESSION);
            db.execSQL(CREATE_X3DHPQ_PAIRING_SESSION_EXPIRY_INDEX);
        }
        // x3dhpq_devicelist_state table (added in DATABASE_VERSION = 58).
        if (oldVersion < 58 && newVersion >= 58) {
            db.execSQL(CREATE_X3DHPQ_DEVICELIST_STATE);
        }
        // x3dhpq_co_account_device table (added in DATABASE_VERSION = 59).
        if (oldVersion < 59 && newVersion >= 59) {
            db.execSQL(CREATE_X3DHPQ_CO_ACCOUNT_DEVICE);
        }
        // x3dhpq_committed_device table (added in DATABASE_VERSION = 60).
        if (oldVersion < 60 && newVersion >= 60) {
            db.execSQL(CREATE_X3DHPQ_COMMITTED_DEVICE);
        }
        // x3dhpq_device_audit table (added in DATABASE_VERSION = 61). No FK to
        // x3dhpq_account_identity — see CREATE_X3DHPQ_DEVICE_AUDIT javadoc.
        if (oldVersion < 61 && newVersion >= 61) {
            db.execSQL(CREATE_X3DHPQ_DEVICE_AUDIT);
        }
        // x3dhpq_manifest_state table (Trust Manifest Phase 2, added in DATABASE_VERSION = 62).
        if (oldVersion < 62 && newVersion >= 62) {
            db.execSQL(CREATE_X3DHPQ_MANIFEST_STATE);
        }
        // messages.x3dhpq_source_device column: author device-id for x3dhpq
        // messages, used to attribute sibling-authored copies (DATABASE_VERSION = 63).
        if (oldVersion < 63 && newVersion >= 63) {
            db.execSQL(
                    "ALTER TABLE "
                            + Message.TABLENAME
                            + " ADD COLUMN "
                            + Message.X3DHPQ_SOURCE_DEVICE
                            + " INTEGER");
        }
        // x3dhpq_group_membership now stores every accepted/authored journal
        // entry keyed by content hash instead of overwriting one latest row.
        if (oldVersion < 64 && newVersion >= 64) {
            db.execSQL("ALTER TABLE x3dhpq_group_membership RENAME TO x3dhpq_group_membership_old");
            db.execSQL(CREATE_X3DHPQ_GROUP_MEMBERSHIP);
            final Cursor c =
                    db.query(
                            "x3dhpq_group_membership_old",
                            null,
                            null,
                            null,
                            null,
                            null,
                            null);
            try {
                while (c.moveToNext()) {
                    final byte[] journalBlob =
                            c.getBlob(c.getColumnIndexOrThrow("journal_blob"));
                    final ContentValues v = new ContentValues();
                    v.put(
                            "account_uuid",
                            c.getString(c.getColumnIndexOrThrow("account_uuid")));
                    v.put("room_jid", c.getString(c.getColumnIndexOrThrow("room_jid")));
                    v.put("entry_hash", x3dhpqJournalEntryContentHash(journalBlob));
                    v.put("journal_blob", journalBlob);
                    v.put("item_id", c.getString(c.getColumnIndexOrThrow("item_id")));
                    v.put("fetched_at", c.getLong(c.getColumnIndexOrThrow("fetched_at")));
                    db.insertWithOnConflict(
                            "x3dhpq_group_membership",
                            null,
                            v,
                            SQLiteDatabase.CONFLICT_REPLACE);
                }
            } finally {
                c.close();
            }
            db.execSQL("DROP TABLE x3dhpq_group_membership_old");
        }
        // KEM pre-keys gain hybrid DIK signatures (spec §9.1, v0.9.0). Existing
        // rows predate the signatures and can't be retroactively signed here
        // (the DIK private key isn't reachable from onUpgrade), so drop and
        // recreate: the local key store repopulates signed KEM pre-keys on the
        // next bootstrap/replenish. Accounts are reset for the beta anyway.
        if (oldVersion < 65 && newVersion >= 65) {
            db.execSQL("DROP TABLE IF EXISTS x3dhpq_kem_pre_key");
            db.execSQL(CREATE_X3DHPQ_KEM_PRE_KEY);
        }
    }

    private static String x3dhpqJournalEntryContentHash(final byte[] entryBytes) {
        try {
            final byte[] h = java.security.MessageDigest.getInstance("SHA-256").digest(entryBytes);
            final StringBuilder sb = new StringBuilder();
            for (final byte b : h) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (final java.security.NoSuchAlgorithmException e) {
            return "len-" + (entryBytes == null ? 0 : entryBytes.length);
        }
    }

    private void canonicalizeJids(SQLiteDatabase db) {
        // migrate db to new, canonicalized JID domainpart representation

        // Conversation table
        Cursor cursor = db.rawQuery("select * from " + Conversation.TABLENAME, new String[0]);
        while (cursor.moveToNext()) {
            String newJid;
            try {
                newJid =
                        Jid.of(
                                        cursor.getString(
                                                cursor.getColumnIndexOrThrow(
                                                        Conversation.CONTACTJID)))
                                .toString();
            } catch (final IllegalArgumentException e) {
                Log.e(
                        Config.LOGTAG,
                        "Failed to migrate Conversation CONTACTJID "
                                + cursor.getString(
                                        cursor.getColumnIndexOrThrow(Conversation.CONTACTJID))
                                + ". Skipping...",
                        e);
                continue;
            }

            final String[] updateArgs = {
                newJid, cursor.getString(cursor.getColumnIndexOrThrow(Conversation.UUID)),
            };
            db.execSQL(
                    "update "
                            + Conversation.TABLENAME
                            + " set "
                            + Conversation.CONTACTJID
                            + " = ? "
                            + " where "
                            + Conversation.UUID
                            + " = ?",
                    updateArgs);
        }
        cursor.close();

        // Contact table
        cursor = db.rawQuery("select * from " + Contact.TABLENAME, new String[0]);
        while (cursor.moveToNext()) {
            String newJid;
            try {
                newJid =
                        Jid.of(cursor.getString(cursor.getColumnIndexOrThrow(Contact.JID)))
                                .toString();
            } catch (final IllegalArgumentException e) {
                Log.e(
                        Config.LOGTAG,
                        "Failed to migrate Contact JID "
                                + cursor.getString(cursor.getColumnIndexOrThrow(Contact.JID))
                                + ":  Skipping...",
                        e);
                continue;
            }

            final String[] updateArgs = {
                newJid,
                cursor.getString(cursor.getColumnIndexOrThrow(Contact.ACCOUNT)),
                cursor.getString(cursor.getColumnIndexOrThrow(Contact.JID)),
            };
            db.execSQL(
                    "update "
                            + Contact.TABLENAME
                            + " set "
                            + Contact.JID
                            + " = ? "
                            + " where "
                            + Contact.ACCOUNT
                            + " = ? "
                            + " AND "
                            + Contact.JID
                            + " = ?",
                    updateArgs);
        }
        cursor.close();

        // Account table
        cursor = db.rawQuery("select * from " + Account.TABLENAME, new String[0]);
        while (cursor.moveToNext()) {
            String newServer;
            try {
                newServer =
                        Jid.of(
                                        cursor.getString(
                                                cursor.getColumnIndexOrThrow(Account.USERNAME)),
                                        cursor.getString(
                                                cursor.getColumnIndexOrThrow(Account.SERVER)),
                                        null)
                                .getDomain()
                                .toString();
            } catch (final IllegalArgumentException e) {
                Log.e(
                        Config.LOGTAG,
                        "Failed to migrate Account SERVER "
                                + cursor.getString(cursor.getColumnIndexOrThrow(Account.SERVER))
                                + ". Skipping...",
                        e);
                continue;
            }

            String[] updateArgs = {
                newServer, cursor.getString(cursor.getColumnIndexOrThrow(Account.UUID)),
            };
            db.execSQL(
                    "update "
                            + Account.TABLENAME
                            + " set "
                            + Account.SERVER
                            + " = ? "
                            + " where "
                            + Account.UUID
                            + " = ?",
                    updateArgs);
        }
        cursor.close();
    }

    public void createConversation(Conversation conversation) {
        SQLiteDatabase db = this.getWritableDatabase();
        db.insert(Conversation.TABLENAME, null, conversation.getContentValues());
    }

    public void createMessage(Message message) {
        SQLiteDatabase db = this.getWritableDatabase();
        db.insert(Message.TABLENAME, null, message.getContentValues());
    }

    public void createAccount(Account account) {
        SQLiteDatabase db = this.getWritableDatabase();
        db.insert(Account.TABLENAME, null, account.getContentValues());
    }

    public void saveResolverResult(String domain, Resolver.Result result) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues contentValues = result.toContentValues();
        contentValues.put(Resolver.Result.DOMAIN, domain);
        db.insert(RESOLVER_RESULTS_TABLENAME, null, contentValues);
    }

    public synchronized Resolver.Result findResolverResult(String domain) {
        SQLiteDatabase db = this.getReadableDatabase();
        String where = Resolver.Result.DOMAIN + "=?";
        String[] whereArgs = {domain};
        final Cursor cursor =
                db.query(RESOLVER_RESULTS_TABLENAME, null, where, whereArgs, null, null, null);
        Resolver.Result result = null;
        if (cursor != null) {
            try {
                if (cursor.moveToFirst()) {
                    result = Resolver.Result.fromCursor(cursor);
                }
            } catch (Exception e) {
                Log.d(
                        Config.LOGTAG,
                        "unable to find cached resolver result in database " + e.getMessage());
                return null;
            } finally {
                cursor.close();
            }
        }
        return result;
    }

    public void insertPresenceTemplate(PresenceTemplate template) {
        SQLiteDatabase db = this.getWritableDatabase();
        String whereToDelete = PresenceTemplate.MESSAGE + "=?";
        String[] whereToDeleteArgs = {template.getStatusMessage()};
        db.delete(PresenceTemplate.TABELNAME, whereToDelete, whereToDeleteArgs);
        db.delete(
                PresenceTemplate.TABELNAME,
                PresenceTemplate.UUID
                        + " not in (select "
                        + PresenceTemplate.UUID
                        + " from "
                        + PresenceTemplate.TABELNAME
                        + " order by "
                        + PresenceTemplate.LAST_USED
                        + " desc limit 9)",
                null);
        db.insert(PresenceTemplate.TABELNAME, null, template.getContentValues());
    }

    public List<PresenceTemplate> getPresenceTemplates() {
        ArrayList<PresenceTemplate> templates = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor =
                db.query(
                        PresenceTemplate.TABELNAME,
                        null,
                        null,
                        null,
                        null,
                        null,
                        PresenceTemplate.LAST_USED + " desc");
        while (cursor.moveToNext()) {
            templates.add(PresenceTemplate.fromCursor(cursor));
        }
        cursor.close();
        return templates;
    }

    public CopyOnWriteArrayList<Conversation> getConversations(int status) {
        CopyOnWriteArrayList<Conversation> list = new CopyOnWriteArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        String[] selectionArgs = {Integer.toString(status)};
        Cursor cursor =
                db.rawQuery(
                        "select * from "
                                + Conversation.TABLENAME
                                + " where "
                                + Conversation.STATUS
                                + " = ? and "
                                + Conversation.CONTACTJID
                                + " is not null order by "
                                + Conversation.CREATED
                                + " desc",
                        selectionArgs);
        while (cursor.moveToNext()) {
            final Conversation conversation = Conversation.fromCursor(cursor);
            if (conversation.getAddress() instanceof Jid.Invalid) {
                continue;
            }
            list.add(conversation);
        }
        cursor.close();
        return list;
    }

    public ArrayList<Message> getMessages(Conversation conversations, int limit) {
        return getMessages(conversations, limit, -1);
    }

    public ArrayList<Message> getMessages(Conversation conversation, int limit, long timestamp) {
        ArrayList<Message> list = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor;
        if (timestamp == -1) {
            String[] selectionArgs = {conversation.getUuid()};
            cursor =
                    db.query(
                            Message.TABLENAME,
                            null,
                            Message.CONVERSATION + "=?",
                            selectionArgs,
                            null,
                            null,
                            Message.TIME_SENT + " DESC",
                            String.valueOf(limit));
        } else {
            String[] selectionArgs = {conversation.getUuid(), Long.toString(timestamp)};
            cursor =
                    db.query(
                            Message.TABLENAME,
                            null,
                            Message.CONVERSATION + "=? and " + Message.TIME_SENT + "<?",
                            selectionArgs,
                            null,
                            null,
                            Message.TIME_SENT + " DESC",
                            String.valueOf(limit));
        }
        CursorUtils.upgradeCursorWindowSize(cursor);
        while (cursor.moveToNext()) {
            try {
                list.add(0, Message.fromCursor(context, cursor, conversation));
            } catch (final Exception e) {
                Log.e(Config.LOGTAG, "unable to restore message", e);
            }
        }
        cursor.close();
        return list;
    }

    public Cursor getMessageSearchCursor(final List<String> term, final String uuid) {
        final SQLiteDatabase db = this.getReadableDatabase();
        final StringBuilder SQL = new StringBuilder();
        final String[] selectionArgs;
        SQL.append(
                "SELECT "
                        + Message.TABLENAME
                        + ".*,"
                        + Conversation.TABLENAME
                        + "."
                        + Conversation.CONTACTJID
                        + ","
                        + Conversation.TABLENAME
                        + "."
                        + Conversation.ACCOUNT
                        + ","
                        + Conversation.TABLENAME
                        + "."
                        + Conversation.MODE
                        + " FROM "
                        + Message.TABLENAME
                        + " JOIN "
                        + Conversation.TABLENAME
                        + " ON "
                        + Message.TABLENAME
                        + "."
                        + Message.CONVERSATION
                        + "="
                        + Conversation.TABLENAME
                        + "."
                        + Conversation.UUID
                        + " JOIN messages_index ON messages_index.rowid=messages.rowid WHERE "
                        + Message.ENCRYPTION
                        + " NOT IN("
                        + Message.ENCRYPTION_X3DHPQ_NOT_FOR_THIS_DEVICE
                        + ","
                        + Message.ENCRYPTION_PGP
                        + ","
                        + Message.ENCRYPTION_DECRYPTION_FAILED
                        + ","
                        + Message.ENCRYPTION_X3DHPQ_FAILED
                        + ") AND "
                        + Message.TYPE
                        + " IN("
                        + Message.TYPE_TEXT
                        + ","
                        + Message.TYPE_PRIVATE
                        + ") AND messages_index.body MATCH ?");
        if (uuid == null) {
            selectionArgs = new String[] {FtsUtils.toMatchString(term)};
        } else {
            selectionArgs = new String[] {FtsUtils.toMatchString(term), uuid};
            SQL.append(" AND " + Conversation.TABLENAME + '.' + Conversation.UUID + "=?");
        }
        SQL.append(" ORDER BY " + Message.TIME_SENT + " DESC limit " + Config.MAX_SEARCH_RESULTS);
        Log.d(Config.LOGTAG, "search term: " + FtsUtils.toMatchString(term));
        return db.rawQuery(SQL.toString(), selectionArgs);
    }

    public List<String> markFileAsDeleted(final File file) {
        final var uuids = getMessagesWithFile(file);
        markFileAsDeleted(uuids);
        return uuids;
    }

    public List<String> getMessagesWithFile(final File file) {
        final var db = this.getReadableDatabase();
        final var selection = Message.RELATIVE_FILE_PATH + "=? and type in (1,2,5)";
        final var selectionArgs = new String[] {file.getAbsolutePath()};
        final var builder = new ImmutableList.Builder<String>();
        try (final var cursor =
                db.query(
                        Message.TABLENAME,
                        new String[] {Message.UUID},
                        selection,
                        selectionArgs,
                        null,
                        null,
                        null)) {
            while (cursor.moveToNext()) {
                builder.add(cursor.getString(0));
            }
        }
        return builder.build();
    }

    private void markFileAsDeleted(final List<String> uuids) {
        SQLiteDatabase db = this.getReadableDatabase();
        final ContentValues contentValues = new ContentValues();
        final String where = Message.UUID + "=?";
        contentValues.put(Message.DELETED, 1);
        db.beginTransaction();
        for (final String uuid : uuids) {
            db.update(Message.TABLENAME, contentValues, where, new String[] {uuid});
        }
        db.setTransactionSuccessful();
        db.endTransaction();
    }

    public void markFilesAsChanged(final List<FilePathInfo> files) {
        SQLiteDatabase db = this.getReadableDatabase();
        final String where = Message.UUID + "=?";
        db.beginTransaction();
        for (final var info : files) {
            final ContentValues contentValues = new ContentValues();
            contentValues.put(Message.DELETED, info.deleted ? 1 : 0);
            db.update(Message.TABLENAME, contentValues, where, new String[] {info.uuid.toString()});
        }
        db.setTransactionSuccessful();
        db.endTransaction();
    }

    public List<FilePathInfo> getFilePathInfo() {
        final var selection = "type in (1,2,5) and relativeFilePath  is not null";
        return getFilePathInfoInternal(selection, null);
    }

    private List<FilePathInfo> getFilePathInfoInternal(
            final String selection, final String[] selectionArgs) {
        final var builder = new ImmutableList.Builder<FilePathInfo>();
        final SQLiteDatabase db = this.getReadableDatabase();
        try (final Cursor cursor =
                db.query(
                        Message.TABLENAME,
                        new String[] {Message.UUID, Message.RELATIVE_FILE_PATH, Message.DELETED},
                        selection,
                        selectionArgs,
                        null,
                        null,
                        null)) {
            while (cursor.moveToNext()) {
                builder.add(
                        new FilePathInfo(
                                cursor.getString(0), cursor.getString(1), cursor.getInt(2) > 0));
            }
        }
        return builder.build();
    }

    public List<FilePath> getRelativeFilePaths(
            final String account, final Jid jid, final int limit) {
        final var db = this.getReadableDatabase();
        final String SQL =
                "select uuid,relativeFilePath from messages where type in (1,2,5) and deleted=0 and"
                    + " relativeFilePath is not null and conversationUuid=(select uuid from"
                    + " conversations where accountUuid=? and (contactJid=? or contactJid like ?))"
                    + " GROUP BY relativeFilePath ORDER BY timeSent desc";
        final String[] args = {account, jid.toString(), jid + "/%"};
        final var builder = new ImmutableList.Builder<FilePath>();
        try (final var cursor = db.rawQuery(SQL + (limit > 0 ? " limit " + limit : ""), args)) {
            while (cursor.moveToNext()) {
                builder.add(new FilePath(cursor.getString(0), cursor.getString(1)));
            }
        }
        return builder.build();
    }

    public Set<String> getExistingUrlsForPath(final String account, final String path) {
        final var builder = new ImmutableList.Builder<Message.FileParams>();
        SQLiteDatabase db = this.getReadableDatabase();
        final String sql =
                "select body from messages join conversations on"
                    + " messages.conversationUuid=conversations.uuid where relativeFilePath=? and"
                    + " conversations.accountUuid=? and messages.status<>0 ORDER BY"
                    + " messages.timeSent desc LIMIT 3";
        final String[] args = {path, account};
        try (final Cursor cursor = db.rawQuery(sql, args)) {
            while (cursor.moveToNext()) {
                builder.add(Message.FileParams.of(cursor.getString(0)));
            }
        }
        final var parameters = builder.build();
        return ImmutableSet.copyOf(
                Collections2.transform(
                        Collections2.filter(parameters, p -> Objects.requireNonNull(p).url != null),
                        p -> Objects.requireNonNull(p).url));
    }

    public Message getMessageWithServerMsgId(
            final Conversation conversation, final String messageId) {
        final var db = this.getReadableDatabase();
        final var sql = "select * from messages where conversationUuid=? and serverMsgId=? LIMIT 1";
        final String[] args = {conversation.getUuid(), messageId};
        final Message message;
        try (final Cursor cursor = db.rawQuery(sql, args)) {
            if (cursor.moveToFirst()) {
                message = Message.fromCursor(context, cursor, conversation);
            } else {
                message = null;
            }
        }
        return message;
    }

    public Message getMessageWithUuidOrRemoteId(
            final Conversation conversation, final String messageId) {
        final var db = this.getReadableDatabase();
        final var sql =
                "select * from messages where conversationUuid=? and (uuid=? OR remoteMsgId=?)"
                        + " LIMIT 1";
        final String[] args = {conversation.getUuid(), messageId, messageId};
        final Message message;
        try (final Cursor cursor = db.rawQuery(sql, args)) {
            if (cursor.moveToFirst()) {
                message = Message.fromCursor(context, cursor, conversation);
            } else {
                message = null;
            }
        }
        return message;
    }

    public Message getIndividualMessage(final String uuid) {
        final var db = this.getReadableDatabase();
        final String sql = "select * from messages where uuid=? LIMIT 1";
        final String[] args = {uuid};
        final Cursor cursor = db.rawQuery(sql, args);
        final Message message;
        if (cursor.moveToFirst()) {
            message = IndividualMessage.fromCursor(context, cursor, null);
        } else {
            message = null;
        }
        cursor.close();
        return message;
    }

    public void insertCapsCache(
            EntityCapabilities.EntityCapsHash caps,
            EntityCapabilities2.EntityCaps2Hash caps2,
            InfoQuery infoQuery) {
        try {
            final var contentValues = new ContentValues();
            contentValues.put("caps", caps.encoded());
            contentValues.put("caps2", caps2.encoded());
            contentValues.put("disco_info", StreamElementWriter.asString(infoQuery));
            getWritableDatabase()
                    .insertWithOnConflict(
                            "caps_cache", null, contentValues, SQLiteDatabase.CONFLICT_REPLACE);
        } catch (final IOException e) {
            Log.w(Config.LOGTAG, "could not write caps to cache", e);
        }
    }

    public InfoQuery getInfoQuery(final EntityCapabilities.Hash hash) {
        final String selection;
        final String[] args;
        if (hash instanceof EntityCapabilities.EntityCapsHash) {
            selection = "caps=?";
            args = new String[] {hash.encoded()};
        } else if (hash instanceof EntityCapabilities2.EntityCaps2Hash) {
            selection = "caps2=?";
            args = new String[] {hash.encoded()};
        } else {
            return null;
        }
        try (final Cursor cursor =
                getReadableDatabase()
                        .query(
                                "caps_cache",
                                new String[] {"disco_info"},
                                selection,
                                args,
                                null,
                                null,
                                null)) {
            if (cursor.moveToFirst()) {
                final var cached = cursor.getString(0);
                try {
                    return XmlElementReader.read(cached, InfoQuery.class);
                } catch (final IOException e) {
                    Log.e(Config.LOGTAG, "could not restore info query from cache", e);
                    return null;
                }
            } else {
                return null;
            }
        }
    }

    public static class FilePath {
        public final UUID uuid;
        public final String path;

        private FilePath(String uuid, String path) {
            this.uuid = UUID.fromString(uuid);
            this.path = path;
        }
    }

    public static class FilePathInfo extends FilePath {
        public boolean deleted;

        private FilePathInfo(String uuid, String path, boolean deleted) {
            super(uuid, path);
            this.deleted = deleted;
        }

        public boolean setDeleted(boolean deleted) {
            final boolean changed = deleted != this.deleted;
            this.deleted = deleted;
            return changed;
        }
    }

    public Conversation findConversation(final String uuid) {
        final var db = this.getReadableDatabase();
        final String[] selectionArgs = {uuid};
        try (final Cursor cursor =
                db.query(
                        Conversation.TABLENAME,
                        null,
                        Conversation.UUID + "=?",
                        selectionArgs,
                        null,
                        null,
                        null)) {
            if (cursor.getCount() == 0) {
                return null;
            }
            cursor.moveToFirst();
            final Conversation conversation = Conversation.fromCursor(cursor);
            if (conversation.getAddress() instanceof Jid.Invalid) {
                return null;
            }
            return conversation;
        }
    }

    public Conversation findConversation(final Account account, final Jid contactJid) {
        final SQLiteDatabase db = this.getReadableDatabase();
        final String[] selectionArgs = {
            account.getUuid(),
            contactJid.asBareJid().toString() + "/%",
            contactJid.asBareJid().toString()
        };
        try (final Cursor cursor =
                db.query(
                        Conversation.TABLENAME,
                        null,
                        Conversation.ACCOUNT
                                + "=? AND ("
                                + Conversation.CONTACTJID
                                + " like ? OR "
                                + Conversation.CONTACTJID
                                + "=?)",
                        selectionArgs,
                        null,
                        null,
                        null)) {
            if (cursor.getCount() == 0) {
                return null;
            }
            cursor.moveToFirst();
            final Conversation conversation = Conversation.fromCursor(cursor);
            if (conversation.getAddress() instanceof Jid.Invalid) {
                return null;
            }
            conversation.setAccount(account);
            return conversation;
        }
    }

    public String findConversationUuid(final Jid account, final Jid jid) {
        final SQLiteDatabase db = this.getReadableDatabase();
        final String[] selectionArgs = {
            account.getLocal(),
            account.getDomain().toString(),
            jid.asBareJid().toString() + "/%",
            jid.asBareJid().toString()
        };
        try (final Cursor cursor =
                db.rawQuery(
                        "SELECT conversations.uuid FROM conversations JOIN accounts ON"
                            + " conversations.accountUuid=accounts.uuid WHERE accounts.username=?"
                            + " AND accounts.server=? AND (contactJid=? OR contactJid LIKE ?)",
                        selectionArgs)) {
            if (cursor.getCount() == 0) {
                return null;
            }
            cursor.moveToFirst();
            return cursor.getString(0);
        }
    }

    public void updateConversation(final Conversation conversation) {
        final SQLiteDatabase db = this.getWritableDatabase();
        final String[] args = {conversation.getUuid()};
        db.update(
                Conversation.TABLENAME,
                conversation.getContentValues(),
                Conversation.UUID + "=?",
                args);
    }

    public List<Account> getAccounts() {
        SQLiteDatabase db = this.getReadableDatabase();
        return getAccounts(db);
    }

    public Collection<Jid> getAccountAddresses() {
        return AccountWithOptions.getAddresses(getAccountWithOptions());
    }

    public Set<AccountWithOptions> getAccountWithOptions() {
        final SQLiteDatabase db = this.getReadableDatabase();
        final var addresses = new ImmutableSet.Builder<AccountWithOptions>();
        final String[] columns = new String[] {Account.USERNAME, Account.SERVER, Account.OPTIONS};
        try (final Cursor cursor =
                db.query(Account.TABLENAME, columns, null, null, null, null, null)) {
            while (cursor.moveToNext()) {
                final var address = Jid.of(cursor.getString(0), cursor.getString(1), null);
                addresses.add(new AccountWithOptions(address, cursor.getInt(2)));
            }
        } catch (final Exception e) {
            return Collections.emptySet();
        }
        return addresses.build();
    }

    private List<Account> getAccounts(final SQLiteDatabase db) {
        final List<Account> list = new ArrayList<>();
        try (final Cursor cursor =
                db.query(Account.TABLENAME, null, null, null, null, null, null)) {
            while (cursor.moveToNext()) {
                list.add(Account.fromCursor(cursor));
            }
        }
        return list;
    }

    public boolean updateAccount(final Account account) {
        final var db = this.getWritableDatabase();
        final String[] args = {account.getUuid()};
        final int rows =
                db.update(Account.TABLENAME, account.getContentValues(), Account.UUID + "=?", args);
        return rows == 1;
    }

    public boolean deleteAccount(final Account account) {
        final var db = this.getWritableDatabase();
        final String[] args = {account.getUuid()};
        final int rows = db.delete(Account.TABLENAME, Account.UUID + "=?", args);
        return rows == 1;
    }

    public boolean updateMessage(final Message message, final boolean includeBody) {
        final var db = this.getWritableDatabase();
        final String[] args = {message.getUuid()};
        final var contentValues = message.getContentValues();
        contentValues.remove(Message.UUID);
        if (!includeBody) {
            contentValues.remove(Message.BODY);
        }
        final int rows = db.update(Message.TABLENAME, contentValues, Message.UUID + "=?", args);
        return rows == 1;
    }

    public boolean updateMessage(final Message message, final String uuid) {
        final var db = this.getWritableDatabase();
        final String[] args = {uuid};
        final int rows =
                db.update(Message.TABLENAME, message.getContentValues(), Message.UUID + "=?", args);
        return rows == 1;
    }

    public boolean deleteMessage(String uuid) {
        final var db = this.getWritableDatabase();
        final String[] args = {uuid};
        final int rows = db.delete(Message.TABLENAME, Account.UUID + "=?", args);
        return rows == 1;
    }

    public Map<Jid, Contact> readRoster(final Account account) {
        final var builder = new ImmutableMap.Builder<Jid, Contact>();
        final SQLiteDatabase db = this.getReadableDatabase();
        final String[] args = {account.getUuid()};
        try (final Cursor cursor =
                db.query(Contact.TABLENAME, null, Contact.ACCOUNT + "=?", args, null, null, null)) {
            while (cursor.moveToNext()) {
                final var contact = Contact.fromCursor(cursor);
                if (contact != null) {
                    contact.setAccount(account);
                    builder.put(contact.getAddress(), contact);
                }
            }
        }
        return builder.buildKeepingLast();
    }

    public void writeRoster(
            final Account account, final String version, final List<Contact> contacts) {
        final long start = SystemClock.elapsedRealtime();
        final SQLiteDatabase db = this.getWritableDatabase();
        db.beginTransaction();
        for (final Contact contact : contacts) {
            if (contact.getOption(Contact.Options.IN_ROSTER)
                    || contact.hasAvatarOrPresenceName()
                    || contact.getOption(Contact.Options.SYNCED_VIA_OTHER)) {
                db.insert(Contact.TABLENAME, null, contact.getContentValues());
            } else {
                String where = Contact.ACCOUNT + "=? AND " + Contact.JID + "=?";
                String[] whereArgs = {account.getUuid(), contact.getAddress().toString()};
                db.delete(Contact.TABLENAME, where, whereArgs);
            }
        }
        db.setTransactionSuccessful();
        db.endTransaction();
        account.setRosterVersion(version);
        updateAccount(account);
        long duration = SystemClock.elapsedRealtime() - start;
        Log.d(
                Config.LOGTAG,
                account.getJid().asBareJid() + ": persisted roster in " + duration + "ms");
    }

    public List<FilePathInfo> deleteMessagesInConversation(final Conversation conversation) {
        long start = SystemClock.elapsedRealtime();
        final SQLiteDatabase db = this.getWritableDatabase();
        db.beginTransaction();
        final String[] args = {conversation.getUuid()};
        final var selection =
                "conversationUuid=? AND type in (1,2,5) AND relativeFilePath is not null AND"
                        + " sharedStorage=false";
        final var filePathInfos = getFilePathInfoInternal(selection, args);
        final int num = db.delete(Message.TABLENAME, Message.CONVERSATION + "=?", args);
        db.setTransactionSuccessful();
        db.endTransaction();
        Log.d(
                Config.LOGTAG,
                "deleted "
                        + num
                        + " messages for "
                        + conversation.getAddress().asBareJid()
                        + " in "
                        + (SystemClock.elapsedRealtime() - start)
                        + "ms");
        updateConversation(conversation);
        return filterUnusedFiles(filePathInfos);
    }

    public List<FilePathInfo> expireOldMessages(final long timestamp) {
        final String[] args = {String.valueOf(timestamp)};
        final var db = this.getWritableDatabase();
        final var selection =
                "type in (1,2,5) AND relativeFilePath is not null AND sharedStorage=false AND"
                        + " timeSent<?";
        final var files = getFilePathInfoInternal(selection, args);
        db.beginTransaction();
        db.delete(Message.TABLENAME, "timeSent<?", args);
        db.setTransactionSuccessful();
        db.endTransaction();
        return filterUnusedFiles(files);
    }

    private List<FilePathInfo> filterUnusedFiles(final List<FilePathInfo> filePathInfos) {
        final var builder = new ImmutableList.Builder<FilePathInfo>();
        for (final var info : filePathInfos) {
            if (Strings.isNullOrEmpty(info.path) || info.deleted) {
                continue;
            }
            if (info.path.charAt(0) == '/') {
                final var uuids = getMessagesWithFile(new File(info.path));
                if (uuids.isEmpty()) {
                    builder.add(info);
                } else {
                    Log.d(Config.LOGTAG, "omitting " + info.path + " used by " + uuids);
                }
            }
        }
        return builder.build();
    }

    public MamReference getLastMessageReceived(Account account) {
        Cursor cursor = null;
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            String sql =
                    "select messages.timeSent,messages.serverMsgId from accounts join conversations"
                        + " on accounts.uuid=conversations.accountUuid join messages on"
                        + " conversations.uuid=messages.conversationUuid where accounts.uuid=? and"
                        + " (messages.status=0 or messages.carbon=1 or messages.serverMsgId not"
                        + " null) and (conversations.mode=0 or (messages.serverMsgId not null and"
                        + " messages.type=4)) order by messages.timesent desc limit 1";
            String[] args = {account.getUuid()};
            cursor = db.rawQuery(sql, args);
            if (cursor.getCount() == 0) {
                return null;
            } else {
                cursor.moveToFirst();
                return new MamReference(cursor.getLong(0), cursor.getString(1));
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    public MamReference getLastClearDate(Account account) {
        SQLiteDatabase db = this.getReadableDatabase();
        String[] columns = {Conversation.ATTRIBUTES};
        String selection = Conversation.ACCOUNT + "=?";
        String[] args = {account.getUuid()};
        Cursor cursor =
                db.query(Conversation.TABLENAME, columns, selection, args, null, null, null);
        MamReference maxClearDate = new MamReference(0);
        while (cursor.moveToNext()) {
            try {
                final JSONObject o = new JSONObject(cursor.getString(0));
                maxClearDate =
                        MamReference.max(
                                maxClearDate,
                                MamReference.fromAttribute(
                                        o.getString(Conversation.ATTRIBUTE_LAST_CLEAR_HISTORY)));
            } catch (Exception e) {
                // ignored
            }
        }
        cursor.close();
        return maxClearDate;
    }

    private void deleteSession(SQLiteDatabase db, Account account, SignalProtocolAddress contact) {
        String[] args = {
            account.getUuid(), contact.getName(), Integer.toString(contact.getDeviceId())
        };
        db.delete(
                AXOLOTL_SESSION_TABLENAME,
                AXOLOTL_ACCOUNT
                        + " = ? AND "
                        + AXOLOTL_NAME
                        + " = ? AND "
                        + AXOLOTL_DEVICE_ID
                        + " = ? ",
                args);
    }

    private Cursor getIdentityKeyCursor(
            SQLiteDatabase db, Account account, String name, boolean own) {
        return getIdentityKeyCursor(db, account, name, own, null);
    }

    private Cursor getIdentityKeyCursor(
            SQLiteDatabase db, Account account, String name, Boolean own, String fingerprint) {
        String[] columns = {
            AXOLOTL_TRUST,
            AXOLOTL_ACTIVE,
            AXOLOTL_LAST_ACTIVATION,
            AXOLOTL_KEY
        };
        ArrayList<String> selectionArgs = new ArrayList<>(4);
        selectionArgs.add(account.getUuid());
        String selectionString = AXOLOTL_ACCOUNT + " = ?";
        if (name != null) {
            selectionArgs.add(name);
            selectionString += " AND " + AXOLOTL_NAME + " = ?";
        }
        if (fingerprint != null) {
            selectionArgs.add(fingerprint);
            selectionString += " AND " + AXOLOTL_FINGERPRINT + " = ?";
        }
        if (own != null) {
            selectionArgs.add(own ? "1" : "0");
            selectionString += " AND " + AXOLOTL_OWN + " = ?";
        }
        Cursor cursor =
                db.query(
                        AXOLOTL_IDENTITIES_TABLENAME,
                        columns,
                        selectionString,
                        selectionArgs.toArray(new String[selectionArgs.size()]),
                        null,
                        null,
                        null);

        return cursor;
    }

    private IdentityKeyPair loadOwnIdentityKeyPair(SQLiteDatabase db, Account account) {
        String name = account.getJid().asBareJid().toString();
        IdentityKeyPair identityKeyPair = null;
        Cursor cursor = getIdentityKeyCursor(db, account, name, true);
        if (cursor.getCount() != 0) {
            cursor.moveToFirst();
            try {
                identityKeyPair =
                        new IdentityKeyPair(
                                Base64.decode(
                                        cursor.getString(
                                                cursor.getColumnIndex(AXOLOTL_KEY)),
                                        Base64.DEFAULT));
            } catch (InvalidKeyException e) {
                Log.d(
                        Config.LOGTAG,
                        "AxolotlService"
                                + ": Encountered invalid IdentityKey in database for account"
                                + account.getJid().asBareJid()
                                + ", address: "
                                + name);
            }
        }
        cursor.close();

        return identityKeyPair;
    }

    private void recreateAxolotlDb(SQLiteDatabase db) {
        Log.d(
                Config.LOGTAG,
                "AxolotlService" + " : " + ">>> (RE)CREATING AXOLOTL DATABASE <<<");
        db.execSQL("DROP TABLE IF EXISTS " + AXOLOTL_SESSION_TABLENAME);
        db.execSQL(CREATE_SESSIONS_STATEMENT);
        db.execSQL("DROP TABLE IF EXISTS " + AXOLOTL_PREKEY_TABLENAME);
        db.execSQL(CREATE_PREKEYS_STATEMENT);
        db.execSQL("DROP TABLE IF EXISTS " + AXOLOTL_SIGNED_PREKEY_TABLENAME);
        db.execSQL(CREATE_SIGNED_PREKEYS_STATEMENT);
        db.execSQL("DROP TABLE IF EXISTS " + AXOLOTL_IDENTITIES_TABLENAME);
        db.execSQL(CREATE_IDENTITIES_STATEMENT);
    }

    public long getLastTimeFingerprintUsed(Account account, String fingerprint) {
        String SQL =
                "select messages.timeSent from accounts join conversations on"
                        + " accounts.uuid=conversations.accountUuid join messages on"
                        + " conversations.uuid=messages.conversationUuid where accounts.uuid=? and"
                        + " messages.axolotl_fingerprint=? order by messages.timesent desc limit 1";
        String[] args = {account.getUuid(), fingerprint};
        Cursor cursor = getReadableDatabase().rawQuery(SQL, args);
        long time;
        if (cursor.moveToFirst()) {
            time = cursor.getLong(0);
        } else {
            time = 0;
        }
        cursor.close();
        return time;
    }

    private Cursor getCursorForSession(Account account, SignalProtocolAddress contact) {
        final SQLiteDatabase db = this.getReadableDatabase();
        String[] selectionArgs = {
            account.getUuid(), contact.getName(), Integer.toString(contact.getDeviceId())
        };
        return db.query(
                AXOLOTL_SESSION_TABLENAME,
                null,
                AXOLOTL_ACCOUNT
                        + " = ? AND "
                        + AXOLOTL_NAME
                        + " = ? AND "
                        + AXOLOTL_DEVICE_ID
                        + " = ? ",
                selectionArgs,
                null,
                null,
                null);
    }

    public SessionRecord loadSession(Account account, SignalProtocolAddress contact) {
        SessionRecord session = null;
        Cursor cursor = getCursorForSession(account, contact);
        if (cursor.getCount() != 0) {
            cursor.moveToFirst();
            try {
                session =
                        new SessionRecord(
                                Base64.decode(
                                        cursor.getString(
                                                cursor.getColumnIndex(AXOLOTL_KEY)),
                                        Base64.DEFAULT));
            } catch (IOException e) {
                cursor.close();
                throw new AssertionError(e);
            }
        }
        cursor.close();
        return session;
    }

    public List<Integer> getSubDeviceSessions(Account account, SignalProtocolAddress contact) {
        final SQLiteDatabase db = this.getReadableDatabase();
        return getSubDeviceSessions(db, account, contact);
    }

    private List<Integer> getSubDeviceSessions(
            SQLiteDatabase db, Account account, SignalProtocolAddress contact) {
        List<Integer> devices = new ArrayList<>();
        String[] columns = {AXOLOTL_DEVICE_ID};
        String[] selectionArgs = {account.getUuid(), contact.getName()};
        Cursor cursor =
                db.query(
                        AXOLOTL_SESSION_TABLENAME,
                        columns,
                        AXOLOTL_ACCOUNT + " = ? AND " + AXOLOTL_NAME + " = ?",
                        selectionArgs,
                        null,
                        null,
                        null);

        while (cursor.moveToNext()) {
            devices.add(cursor.getInt(cursor.getColumnIndex(AXOLOTL_DEVICE_ID)));
        }

        cursor.close();
        return devices;
    }

    public List<String> getKnownSignalAddresses(Account account) {
        List<String> addresses = new ArrayList<>();
        String[] colums = {"DISTINCT " + AXOLOTL_NAME};
        String[] selectionArgs = {account.getUuid()};
        Cursor cursor =
                getReadableDatabase()
                        .query(
                                AXOLOTL_SESSION_TABLENAME,
                                colums,
                                AXOLOTL_ACCOUNT + " = ?",
                                selectionArgs,
                                null,
                                null,
                                null);
        while (cursor.moveToNext()) {
            addresses.add(cursor.getString(0));
        }
        cursor.close();
        return addresses;
    }

    public boolean containsSession(Account account, SignalProtocolAddress contact) {
        Cursor cursor = getCursorForSession(account, contact);
        int count = cursor.getCount();
        cursor.close();
        return count != 0;
    }

    public void storeSession(
            Account account, SignalProtocolAddress contact, SessionRecord session) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(AXOLOTL_NAME, contact.getName());
        values.put(AXOLOTL_DEVICE_ID, contact.getDeviceId());
        values.put(
                AXOLOTL_KEY, Base64.encodeToString(session.serialize(), Base64.DEFAULT));
        values.put(AXOLOTL_ACCOUNT, account.getUuid());
        db.insert(AXOLOTL_SESSION_TABLENAME, null, values);
    }

    public void deleteSession(Account account, SignalProtocolAddress contact) {
        SQLiteDatabase db = this.getWritableDatabase();
        deleteSession(db, account, contact);
    }

    public void deleteAllSessions(Account account, SignalProtocolAddress contact) {
        SQLiteDatabase db = this.getWritableDatabase();
        String[] args = {account.getUuid(), contact.getName()};
        db.delete(
                AXOLOTL_SESSION_TABLENAME,
                AXOLOTL_ACCOUNT + "=? AND " + AXOLOTL_NAME + " = ?",
                args);
    }

    private Cursor getCursorForPreKey(Account account, int preKeyId) {
        SQLiteDatabase db = this.getReadableDatabase();
        String[] columns = {AXOLOTL_KEY};
        String[] selectionArgs = {account.getUuid(), Integer.toString(preKeyId)};
        Cursor cursor =
                db.query(
                        AXOLOTL_PREKEY_TABLENAME,
                        columns,
                        AXOLOTL_ACCOUNT + "=? AND " + AXOLOTL_ID + "=?",
                        selectionArgs,
                        null,
                        null,
                        null);

        return cursor;
    }

    public PreKeyRecord loadPreKey(Account account, int preKeyId) {
        PreKeyRecord record = null;
        Cursor cursor = getCursorForPreKey(account, preKeyId);
        if (cursor.getCount() != 0) {
            cursor.moveToFirst();
            try {
                record =
                        new PreKeyRecord(
                                Base64.decode(
                                        cursor.getString(
                                                cursor.getColumnIndex(AXOLOTL_KEY)),
                                        Base64.DEFAULT));
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }
        cursor.close();
        return record;
    }

    public boolean containsPreKey(Account account, int preKeyId) {
        Cursor cursor = getCursorForPreKey(account, preKeyId);
        int count = cursor.getCount();
        cursor.close();
        return count != 0;
    }

    public void storePreKey(Account account, PreKeyRecord record) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(AXOLOTL_ID, record.getId());
        values.put(
                AXOLOTL_KEY, Base64.encodeToString(record.serialize(), Base64.DEFAULT));
        values.put(AXOLOTL_ACCOUNT, account.getUuid());
        db.insert(AXOLOTL_PREKEY_TABLENAME, null, values);
    }

    public int deletePreKey(Account account, int preKeyId) {
        SQLiteDatabase db = this.getWritableDatabase();
        String[] args = {account.getUuid(), Integer.toString(preKeyId)};
        return db.delete(
                AXOLOTL_PREKEY_TABLENAME,
                AXOLOTL_ACCOUNT + "=? AND " + AXOLOTL_ID + "=?",
                args);
    }

    private Cursor getCursorForSignedPreKey(Account account, int signedPreKeyId) {
        SQLiteDatabase db = this.getReadableDatabase();
        String[] columns = {AXOLOTL_KEY};
        String[] selectionArgs = {account.getUuid(), Integer.toString(signedPreKeyId)};
        Cursor cursor =
                db.query(
                        AXOLOTL_SIGNED_PREKEY_TABLENAME,
                        columns,
                        AXOLOTL_ACCOUNT + "=? AND " + AXOLOTL_ID + "=?",
                        selectionArgs,
                        null,
                        null,
                        null);

        return cursor;
    }

    public SignedPreKeyRecord loadSignedPreKey(Account account, int signedPreKeyId) {
        SignedPreKeyRecord record = null;
        Cursor cursor = getCursorForSignedPreKey(account, signedPreKeyId);
        if (cursor.getCount() != 0) {
            cursor.moveToFirst();
            try {
                record =
                        new SignedPreKeyRecord(
                                Base64.decode(
                                        cursor.getString(
                                                cursor.getColumnIndex(AXOLOTL_KEY)),
                                        Base64.DEFAULT));
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        }
        cursor.close();
        return record;
    }

    public List<SignedPreKeyRecord> loadSignedPreKeys(Account account) {
        List<SignedPreKeyRecord> prekeys = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        String[] columns = {AXOLOTL_KEY};
        String[] selectionArgs = {account.getUuid()};
        Cursor cursor =
                db.query(
                        AXOLOTL_SIGNED_PREKEY_TABLENAME,
                        columns,
                        AXOLOTL_ACCOUNT + "=?",
                        selectionArgs,
                        null,
                        null,
                        null);

        while (cursor.moveToNext()) {
            try {
                prekeys.add(
                        new SignedPreKeyRecord(
                                Base64.decode(
                                        cursor.getString(
                                                cursor.getColumnIndex(AXOLOTL_KEY)),
                                        Base64.DEFAULT)));
            } catch (IOException ignored) {
            }
        }
        cursor.close();
        return prekeys;
    }

    public int getSignedPreKeysCount(Account account) {
        String[] columns = {"count(" + AXOLOTL_KEY + ")"};
        String[] selectionArgs = {account.getUuid()};
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor =
                db.query(
                        AXOLOTL_SIGNED_PREKEY_TABLENAME,
                        columns,
                        AXOLOTL_ACCOUNT + "=?",
                        selectionArgs,
                        null,
                        null,
                        null);
        final int count;
        if (cursor.moveToFirst()) {
            count = cursor.getInt(0);
        } else {
            count = 0;
        }
        cursor.close();
        return count;
    }

    public boolean containsSignedPreKey(Account account, int signedPreKeyId) {
        Cursor cursor = getCursorForPreKey(account, signedPreKeyId);
        int count = cursor.getCount();
        cursor.close();
        return count != 0;
    }

    public void storeSignedPreKey(Account account, SignedPreKeyRecord record) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(AXOLOTL_ID, record.getId());
        values.put(
                AXOLOTL_KEY, Base64.encodeToString(record.serialize(), Base64.DEFAULT));
        values.put(AXOLOTL_ACCOUNT, account.getUuid());
        db.insert(AXOLOTL_SIGNED_PREKEY_TABLENAME, null, values);
    }

    public void deleteSignedPreKey(Account account, int signedPreKeyId) {
        SQLiteDatabase db = this.getWritableDatabase();
        String[] args = {account.getUuid(), Integer.toString(signedPreKeyId)};
        db.delete(
                AXOLOTL_SIGNED_PREKEY_TABLENAME,
                AXOLOTL_ACCOUNT + "=? AND " + AXOLOTL_ID + "=?",
                args);
    }

    private Cursor getIdentityKeyCursor(Account account, String name, boolean own) {
        final SQLiteDatabase db = this.getReadableDatabase();
        return getIdentityKeyCursor(db, account, name, own);
    }

    private Cursor getIdentityKeyCursor(Account account, String fingerprint) {
        final SQLiteDatabase db = this.getReadableDatabase();
        return getIdentityKeyCursor(db, account, fingerprint);
    }

    private Cursor getIdentityKeyCursor(SQLiteDatabase db, Account account, String fingerprint) {
        return getIdentityKeyCursor(db, account, null, null, fingerprint);
    }

    public IdentityKeyPair loadOwnIdentityKeyPair(Account account) {
        SQLiteDatabase db = getReadableDatabase();
        return loadOwnIdentityKeyPair(db, account);
    }

    public Set<IdentityKey> loadIdentityKeys(Account account, String name) {
        return loadIdentityKeys(account, name, null);
    }

    public Set<IdentityKey> loadIdentityKeys(
            Account account, String name, FingerprintStatus status) {
        Set<IdentityKey> identityKeys = new HashSet<>();
        Cursor cursor = getIdentityKeyCursor(account, name, false);

        while (cursor.moveToNext()) {
            if (status != null && !FingerprintStatus.fromCursor(cursor).equals(status)) {
                continue;
            }
            try {
                String key = cursor.getString(cursor.getColumnIndex(AXOLOTL_KEY));
                if (key != null) {
                    identityKeys.add(new IdentityKey(Base64.decode(key, Base64.DEFAULT), 0));
                } else {
                    Log.d(
                            Config.LOGTAG,
                            AxolotlService.getLogprefix(account)
                                    + "Missing key (possibly preverified) in database for account"
                                    + account.getJid().asBareJid()
                                    + ", address: "
                                    + name);
                }
            } catch (InvalidKeyException e) {
                Log.d(
                        Config.LOGTAG,
                        AxolotlService.getLogprefix(account)
                                + "Encountered invalid IdentityKey in database for account"
                                + account.getJid().asBareJid()
                                + ", address: "
                                + name);
            }
        }
        cursor.close();

        return identityKeys;
    }

    public long numTrustedKeys(Account account, String name) {
        SQLiteDatabase db = getReadableDatabase();
        String[] args = {
            account.getUuid(),
            name,
            FingerprintStatus.Trust.TRUSTED.toString(),
            FingerprintStatus.Trust.VERIFIED.toString(),
            FingerprintStatus.Trust.VERIFIED_X509.toString()
        };
        return DatabaseUtils.queryNumEntries(
                db,
                AXOLOTL_IDENTITIES_TABLENAME,
                AXOLOTL_ACCOUNT
                        + " = ?"
                        + " AND "
                        + AXOLOTL_NAME
                        + " = ?"
                        + " AND ("
                        + AXOLOTL_TRUST
                        + " = ? OR "
                        + AXOLOTL_TRUST
                        + " = ? OR "
                        + AXOLOTL_TRUST
                        + " = ?)"
                        + " AND "
                        + AXOLOTL_ACTIVE
                        + " > 0",
                args);
    }

    private void storeIdentityKey(
            Account account,
            String name,
            boolean own,
            String fingerprint,
            String base64Serialized,
            FingerprintStatus status) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(AXOLOTL_ACCOUNT, account.getUuid());
        values.put(AXOLOTL_NAME, name);
        values.put(AXOLOTL_OWN, own ? 1 : 0);
        values.put(AXOLOTL_FINGERPRINT, fingerprint);
        values.put(AXOLOTL_KEY, base64Serialized);
        values.putAll(status.toContentValues());
        String where =
                AXOLOTL_ACCOUNT
                        + "=? AND "
                        + AXOLOTL_NAME
                        + "=? AND "
                        + AXOLOTL_FINGERPRINT
                        + " =?";
        String[] whereArgs = {account.getUuid(), name, fingerprint};
        int rows = db.update(AXOLOTL_IDENTITIES_TABLENAME, values, where, whereArgs);
        if (rows == 0) {
            db.insert(AXOLOTL_IDENTITIES_TABLENAME, null, values);
        }
    }

    public void storePreVerification(
            Account account, String name, String fingerprint, FingerprintStatus status) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(AXOLOTL_ACCOUNT, account.getUuid());
        values.put(AXOLOTL_NAME, name);
        values.put(AXOLOTL_OWN, 0);
        values.put(AXOLOTL_FINGERPRINT, fingerprint);
        values.putAll(status.toContentValues());
        db.insert(AXOLOTL_IDENTITIES_TABLENAME, null, values);
    }

    public FingerprintStatus getFingerprintStatus(Account account, String fingerprint) {
        Cursor cursor = getIdentityKeyCursor(account, fingerprint);
        final FingerprintStatus status;
        if (cursor.getCount() > 0) {
            cursor.moveToFirst();
            status = FingerprintStatus.fromCursor(cursor);
        } else {
            status = null;
        }
        cursor.close();
        return status;
    }

    public boolean setIdentityKeyTrust(
            Account account, String fingerprint, FingerprintStatus fingerprintStatus) {
        SQLiteDatabase db = this.getWritableDatabase();
        return setIdentityKeyTrust(db, account, fingerprint, fingerprintStatus);
    }

    private boolean setIdentityKeyTrust(
            SQLiteDatabase db, Account account, String fingerprint, FingerprintStatus status) {
        String[] selectionArgs = {account.getUuid(), fingerprint};
        int rows =
                db.update(
                        AXOLOTL_IDENTITIES_TABLENAME,
                        status.toContentValues(),
                        AXOLOTL_ACCOUNT
                                + " = ? AND "
                                + AXOLOTL_FINGERPRINT
                                + " = ? ",
                        selectionArgs);
        return rows == 1;
    }

    public boolean setIdentityKeyCertificate(
            Account account, String fingerprint, X509Certificate x509Certificate) {
        SQLiteDatabase db = this.getWritableDatabase();
        String[] selectionArgs = {account.getUuid(), fingerprint};
        try {
            ContentValues values = new ContentValues();
            values.put(AXOLOTL_CERTIFICATE, x509Certificate.getEncoded());
            return db.update(
                            AXOLOTL_IDENTITIES_TABLENAME,
                            values,
                            AXOLOTL_ACCOUNT
                                    + " = ? AND "
                                    + AXOLOTL_FINGERPRINT
                                    + " = ? ",
                            selectionArgs)
                    == 1;
        } catch (CertificateEncodingException e) {
            Log.d(Config.LOGTAG, "could not encode certificate");
            return false;
        }
    }

    public X509Certificate getIdentityKeyCertifcate(Account account, String fingerprint) {
        SQLiteDatabase db = this.getReadableDatabase();
        String[] selectionArgs = {account.getUuid(), fingerprint};
        String[] colums = {AXOLOTL_CERTIFICATE};
        String selection =
                AXOLOTL_ACCOUNT + " = ? AND " + AXOLOTL_FINGERPRINT + " = ? ";
        Cursor cursor =
                db.query(
                        AXOLOTL_IDENTITIES_TABLENAME,
                        colums,
                        selection,
                        selectionArgs,
                        null,
                        null,
                        null);
        if (cursor.getCount() < 1) {
            return null;
        } else {
            cursor.moveToFirst();
            byte[] certificate =
                    cursor.getBlob(cursor.getColumnIndex(AXOLOTL_CERTIFICATE));
            cursor.close();
            if (certificate == null || certificate.length == 0) {
                return null;
            }
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                return (X509Certificate)
                        certificateFactory.generateCertificate(
                                new ByteArrayInputStream(certificate));
            } catch (CertificateException e) {
                Log.d(Config.LOGTAG, "certificate exception " + e.getMessage());
                return null;
            }
        }
    }

    public void storeIdentityKey(
            Account account, String name, IdentityKey identityKey, FingerprintStatus status) {
        storeIdentityKey(
                account,
                name,
                false,
                CryptoHelper.bytesToHex(identityKey.getPublicKey().serialize()),
                Base64.encodeToString(identityKey.serialize(), Base64.DEFAULT),
                status);
    }

    public void storeOwnIdentityKeyPair(Account account, IdentityKeyPair identityKeyPair) {
        storeIdentityKey(
                account,
                account.getJid().asBareJid().toString(),
                true,
                CryptoHelper.bytesToHex(identityKeyPair.getPublicKey().serialize()),
                Base64.encodeToString(identityKeyPair.serialize(), Base64.DEFAULT),
                FingerprintStatus.createActiveVerified(false));
    }

    public void wipeAxolotlDb(Account account) {
        String accountName = account.getUuid();
        Log.d(
                Config.LOGTAG,
                AxolotlService.getLogprefix(account)
                        + ">>> WIPING AXOLOTL DATABASE FOR ACCOUNT "
                        + accountName
                        + " <<<");
        SQLiteDatabase db = this.getWritableDatabase();
        String[] deleteArgs = {accountName};
        db.delete(
                AXOLOTL_SESSION_TABLENAME,
                AXOLOTL_ACCOUNT + " = ?",
                deleteArgs);
        db.delete(
                AXOLOTL_PREKEY_TABLENAME,
                AXOLOTL_ACCOUNT + " = ?",
                deleteArgs);
        db.delete(
                AXOLOTL_SIGNED_PREKEY_TABLENAME,
                AXOLOTL_ACCOUNT + " = ?",
                deleteArgs);
        db.delete(
                AXOLOTL_IDENTITIES_TABLENAME,
                AXOLOTL_ACCOUNT + " = ?",
                deleteArgs);
    }

    public List<ShortcutService.FrequentContact> getFrequentContacts(final int days) {
        final var db = this.getReadableDatabase();
        final String SQL =
                "select "
                        + Conversation.TABLENAME
                        + "."
                        + Conversation.UUID
                        + ","
                        + Conversation.TABLENAME
                        + "."
                        + Conversation.ACCOUNT
                        + ","
                        + Conversation.TABLENAME
                        + "."
                        + Conversation.CONTACTJID
                        + " from "
                        + Conversation.TABLENAME
                        + " join "
                        + Message.TABLENAME
                        + " on conversations.uuid=messages.conversationUuid where"
                        + " messages.status!=0 and carbon==0  and conversations.mode=0 and"
                        + " messages.timeSent>=? group by conversations.uuid order by count(body)"
                        + " desc limit 6;";

        // ^ we only want 4 but we are removing self contacts in a later step

        final String[] whereArgs =
                new String[] {
                    String.valueOf(System.currentTimeMillis() - (Config.MILLISECONDS_IN_DAY * days))
                };
        final var builder = new ImmutableList.Builder<ShortcutService.FrequentContact>();
        try (final var cursor = db.rawQuery(SQL, whereArgs)) {

            while (cursor.moveToNext()) {
                builder.add(
                        new ShortcutService.FrequentContact(
                                cursor.getString(0),
                                cursor.getString(1),
                                Jid.of(cursor.getString(2))));
            }
        }
        return builder.build();
    }

    public record AccountWithOptions(Jid jid, int options) {
        public boolean isOptionSet(final int option) {
            return ((options & (1 << option)) != 0);
        }

        public static boolean hasEnabledAccount(final Collection<AccountWithOptions> accounts) {
            return Iterables.any(
                    accounts,
                    a ->
                            !Objects.requireNonNull(a).isOptionSet(Account.OPTION_DISABLED)
                                    && !a.isOptionSet(Account.OPTION_SOFT_DISABLED));
        }

        public static Collection<Jid> getAddresses(final Collection<AccountWithOptions> accounts) {
            return Collections2.transform(accounts, a -> Objects.requireNonNull(a).jid);
        }
    }

    // ---- x3dhpq row records ----

    public record X3dhpqAccountIdentityRow(
            String accountUuid, byte[] aikPriv, byte[] aikPub, String fingerprint) {}

    public record X3dhpqDeviceListStateRow(
            String accountUuid,
            String ownerJid,
            long version,
            byte[] contentHash,
            boolean acceptedSigned) {}

    // Trust Manifest Phase 2 per-owner rollback/fork guard state (contract §C.3).
    public record X3dhpqManifestStateRow(
            String accountUuid,
            String ownerJid,
            long version,
            byte[] blobHash,
            byte[] blob) {}

    public record X3dhpqLocalDeviceRow(
            String accountUuid,
            int deviceId,
            byte[] dikPriv,
            byte[] dc,
            long createdAt,
            int flags) {}

    // A device under this account's AIK that this install did not generate itself
    // (e.g. enrolled via pairing while acting as the existing/primary side). No
    // private key: dc is the public DeviceCertificate issued to the enrolled device.
    public record X3dhpqCoAccountDeviceRow(
            String accountUuid,
            int deviceId,
            byte[] dc,
            long addedAt,
            int flags) {}

    public record X3dhpqSignedPreKeyRow(
            String accountUuid,
            int keyId,
            byte[] pubX25519,
            byte[] privX25519,
            byte[] sigEd25519,
            byte[] sigMldsa,
            long createdAt) {}

    public record X3dhpqKemPreKeyRow(
            String accountUuid, int keyId, byte[] publicKey, byte[] privateKey,
            byte[] sigEd25519, byte[] sigMldsa) {}

    public record X3dhpqOneTimePreKeyRow(
            String accountUuid,
            int keyId,
            byte[] pubX25519,
            byte[] privX25519,
            boolean consumed) {}

    public record X3dhpqRemoteDeviceRow(
            String accountUuid,
            String peerJid,
            int deviceId,
            byte[] certMarshal,
            Long lastSeen) {}

    public record X3dhpqRemoteBundleRow(
            String accountUuid,
            String peerJid,
            int deviceId,
            byte[] aikPubMarshal,
            byte[] bundleXml,
            long fetchedAt) {}

    public record X3dhpqSessionRow(
            String accountUuid,
            String peerJid,
            int deviceId,
            byte[] stateBlob,
            long updatedAt) {}

    public record X3dhpqGroupSessionRow(
            String accountUuid,
            String roomJid,
            long epoch,
            byte[] stateBlob,
            long updatedAt) {}

    public record X3dhpqGroupMembershipRow(
            String accountUuid,
            String roomJid,
            String entryHash,
            byte[] journalBlob,
            String itemId,
            long fetchedAt) {}

    public record X3dhpqPairingSessionRow(
            byte[] sid,
            String accountUuid,
            int role,
            String peerJid,
            String code,
            byte[] stateBlob,
            long expiresAt) {}

    // A single device-audit DAG entry (§11.7): entryBlob is the opaque
    // DeviceAuditEntryV2.marshal() bytes, entryHashHex is hex(SHA-256(entryBlob)).
    public record X3dhpqDeviceAuditEntryRow(
            String accountUuid, String entryHashHex, byte[] entryBlob, long createdAt) {}

    // ---- x3dhpq transaction helpers ----

    // Begins a write transaction; pair with setTransactionSuccessful()/endTransaction().
    public void beginTransaction() {
        getWritableDatabase().beginTransaction();
    }

    // Marks the current transaction as successful.
    public void setTransactionSuccessful() {
        getWritableDatabase().setTransactionSuccessful();
    }

    // Ends the current transaction; commits if setTransactionSuccessful() was called.
    public void endTransaction() {
        getWritableDatabase().endTransaction();
    }

    // ---- x3dhpq at-rest encryption ----
    // Secret private-key columns are wrapped with a hardware-backed AES-256-GCM key
    // (AndroidKeyStore) before storage and unwrapped on read. Legacy plaintext rows pass
    // through unchanged and are re-wrapped on the next write. Only secret columns are routed
    // through here; public/queryable columns are stored as-is.

    private static byte[] x3dhpqWrap(final byte[] plaintext) {
        return eu.siacs.conversations.crypto.x3dhpq.X3dhpqKeyVault.getInstance().wrap(plaintext);
    }

    private static byte[] x3dhpqUnwrap(final byte[] blob) {
        return eu.siacs.conversations.crypto.x3dhpq.X3dhpqKeyVault.getInstance().unwrap(blob);
    }

    // ---- x3dhpq DAO: account_identity ----

    public void putX3dhpqAccountIdentity(
            String accountUuid, byte[] aikPriv, byte[] aikPub, String fingerprint) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("aik_priv_marshal", x3dhpqWrap(aikPriv));
        v.put("aik_pub_marshal", aikPub);
        v.put("fingerprint", fingerprint);
        // UPDATE-in-place when the row exists; only INSERT when it does not. Adopting the
        // account AIK (e.g. a newcomer embracing membership) MUST NOT delete-and-reinsert the
        // identity row: every x3dhpq child table (local_device, co_account_device,
        // manifest_state, remote_device, ...) is FK'd to account_uuid ON DELETE CASCADE, so a
        // CONFLICT_REPLACE here silently wiped this device's own bootstrapped local device +
        // adopted manifest, stranding a freshly-paired device with an AIK pub but no identity.
        // Intentional resets wipe children via the explicit deleteX3dhpqAccountIdentity(), not
        // through this method.
        final int updated =
                db.update(
                        "x3dhpq_account_identity",
                        v,
                        "account_uuid = ?",
                        new String[] {accountUuid});
        if (updated == 0) {
            v.put("account_uuid", accountUuid);
            db.insertWithOnConflict(
                    "x3dhpq_account_identity", null, v, SQLiteDatabase.CONFLICT_REPLACE);
        }
    }

    public void deleteX3dhpqAccountIdentity(String accountUuid) {
        final SQLiteDatabase db = getWritableDatabase();
        // FK ON DELETE CASCADE removes this account's local devices + prekeys too.
        db.delete("x3dhpq_account_identity", "account_uuid=?", new String[] {accountUuid});
    }

    public X3dhpqAccountIdentityRow loadX3dhpqAccountIdentity(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_account_identity",
                        null,
                        "account_uuid=?",
                        new String[] {accountUuid},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqAccountIdentityRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    x3dhpqUnwrap(c.getBlob(c.getColumnIndexOrThrow("aik_priv_marshal"))),
                    c.getBlob(c.getColumnIndexOrThrow("aik_pub_marshal")),
                    c.getString(c.getColumnIndexOrThrow("fingerprint")));
        } finally {
            c.close();
        }
    }

    // ---- x3dhpq DAO: devicelist_state (§8.2, §8.5) ----

    public void putX3dhpqDeviceListState(
            String accountUuid,
            String ownerJid,
            long version,
            byte[] contentHash,
            boolean acceptedSigned,
            long updatedAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("owner_jid", ownerJid);
        v.put("version", version);
        v.put("content_hash", contentHash != null ? contentHash : new byte[0]);
        v.put("accepted_signed", acceptedSigned ? 1 : 0);
        v.put("updated_at", updatedAt);
        db.insertWithOnConflict(
                "x3dhpq_devicelist_state", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqDeviceListStateRow loadX3dhpqDeviceListState(String accountUuid, String ownerJid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_devicelist_state",
                        null,
                        "account_uuid=? AND owner_jid=?",
                        new String[] {accountUuid, ownerJid},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqDeviceListStateRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getString(c.getColumnIndexOrThrow("owner_jid")),
                    c.getLong(c.getColumnIndexOrThrow("version")),
                    c.getBlob(c.getColumnIndexOrThrow("content_hash")),
                    c.getInt(c.getColumnIndexOrThrow("accepted_signed")) != 0);
        } finally {
            c.close();
        }
    }

    // ---- x3dhpq DAO: trust-manifest state (Phase 2, contract §C.3) ----

    public void putX3dhpqManifestState(
            String accountUuid,
            String ownerJid,
            long version,
            byte[] blobHash,
            byte[] blob,
            long updatedAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("owner_jid", ownerJid);
        v.put("version", version);
        v.put("blob_hash", blobHash != null ? blobHash : new byte[0]);
        v.put("blob", blob != null ? blob : new byte[0]);
        v.put("updated_at", updatedAt);
        db.insertWithOnConflict(
                "x3dhpq_manifest_state", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    /** Drops the manifest-state row for an owner so the NEXT manifest is pinned fresh (re-trust / reset). */
    public void deleteX3dhpqManifestState(String accountUuid, String ownerJid) {
        final SQLiteDatabase db = getWritableDatabase();
        db.delete(
                "x3dhpq_manifest_state",
                "account_uuid=? AND owner_jid=?",
                new String[] {accountUuid, ownerJid});
    }

    public X3dhpqManifestStateRow loadX3dhpqManifestState(String accountUuid, String ownerJid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_manifest_state",
                        null,
                        "account_uuid=? AND owner_jid=?",
                        new String[] {accountUuid, ownerJid},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqManifestStateRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getString(c.getColumnIndexOrThrow("owner_jid")),
                    c.getLong(c.getColumnIndexOrThrow("version")),
                    c.getBlob(c.getColumnIndexOrThrow("blob_hash")),
                    c.getBlob(c.getColumnIndexOrThrow("blob")));
        } finally {
            c.close();
        }
    }

    // ---- x3dhpq DAO: local_device ----

    public void putX3dhpqLocalDevice(
            String accountUuid,
            int deviceId,
            byte[] dikPriv,
            byte[] dc,
            long createdAt,
            int flags) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("device_id", deviceId);
        v.put("dik_priv_marshal", x3dhpqWrap(dikPriv));
        v.put("dc_marshal", dc);
        v.put("created_at", createdAt);
        v.put("flags", flags);
        db.insertWithOnConflict(
                "x3dhpq_local_device", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    /** Deletes the local device key material for a single device (§8.6 revocation). */
    public void deleteX3dhpqLocalDevice(String accountUuid, int deviceId) {
        final SQLiteDatabase db = getWritableDatabase();
        db.delete(
                "x3dhpq_local_device",
                "account_uuid=? AND device_id=?",
                new String[] {accountUuid, Integer.toString(deviceId)});
    }

    public List<X3dhpqLocalDeviceRow> listX3dhpqLocalDevices(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_local_device",
                        null,
                        "account_uuid=?",
                        new String[] {accountUuid},
                        null,
                        null,
                        null);
        final List<X3dhpqLocalDeviceRow> result = new ArrayList<>();
        try {
            while (c.moveToNext()) {
                result.add(
                        new X3dhpqLocalDeviceRow(
                                c.getString(c.getColumnIndexOrThrow("account_uuid")),
                                c.getInt(c.getColumnIndexOrThrow("device_id")),
                                x3dhpqUnwrap(
                                        c.getBlob(c.getColumnIndexOrThrow("dik_priv_marshal"))),
                                c.getBlob(c.getColumnIndexOrThrow("dc_marshal")),
                                c.getLong(c.getColumnIndexOrThrow("created_at")),
                                c.getInt(c.getColumnIndexOrThrow("flags"))));
            }
        } finally {
            c.close();
        }
        return result;
    }

    // ---- x3dhpq DAO: co_account_device ----

    /**
     * Persists a co-account device (§8.2 union set): a device enrolled under this
     * account's AIK that this install did not generate itself — e.g. a newly paired
     * device when acting as the existing/primary side. Holds only the public DC;
     * the private key lives on the enrolled device, never here.
     */
    public void putX3dhpqCoAccountDevice(
            String accountUuid, int deviceId, byte[] dc, long addedAt, int flags) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("device_id", deviceId);
        v.put("dc_marshal", dc);
        v.put("added_at", addedAt);
        v.put("flags", flags);
        db.insertWithOnConflict(
                "x3dhpq_co_account_device", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    /** Deletes a single co-account device row (§8.6 revocation; mirrors deleteX3dhpqLocalDevice). */
    public void deleteX3dhpqCoAccountDevice(String accountUuid, int deviceId) {
        final SQLiteDatabase db = getWritableDatabase();
        db.delete(
                "x3dhpq_co_account_device",
                "account_uuid=? AND device_id=?",
                new String[] {accountUuid, Integer.toString(deviceId)});
    }

    /**
     * Drop every x3dhpq_co_account_device row for {@code accountUuid} whose
     * deviceId is NOT in {@code keepIds}. Called after processing the account's
     * OWN authoritative devicelist so a device the account itself dropped does
     * not linger in the co-account set and get resurrected on the next publish.
     */
    public void pruneX3dhpqCoAccountDevicesNotIn(
            String accountUuid, java.util.Collection<Integer> keepIds) {
        final SQLiteDatabase db = getWritableDatabase();
        // Build "id NOT IN (?, ?, ...)" — empty keepIds means "drop all rows
        // for this account".
        if (keepIds == null || keepIds.isEmpty()) {
            db.delete("x3dhpq_co_account_device",
                    "account_uuid=?",
                    new String[] {accountUuid});
            return;
        }
        final StringBuilder placeholders = new StringBuilder();
        final String[] args = new String[keepIds.size() + 1];
        args[0] = accountUuid;
        int i = 1;
        for (Integer id : keepIds) {
            if (placeholders.length() > 0) placeholders.append(',');
            placeholders.append('?');
            args[i++] = Integer.toString(id);
        }
        final String where = "account_uuid=? AND device_id NOT IN (" + placeholders + ")";
        db.delete("x3dhpq_co_account_device", where, args);
    }

    public List<X3dhpqCoAccountDeviceRow> listX3dhpqCoAccountDevices(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_co_account_device",
                        null,
                        "account_uuid=?",
                        new String[] {accountUuid},
                        null,
                        null,
                        null);
        final List<X3dhpqCoAccountDeviceRow> result = new ArrayList<>();
        try {
            while (c.moveToNext()) {
                result.add(
                        new X3dhpqCoAccountDeviceRow(
                                c.getString(c.getColumnIndexOrThrow("account_uuid")),
                                c.getInt(c.getColumnIndexOrThrow("device_id")),
                                c.getBlob(c.getColumnIndexOrThrow("dc_marshal")),
                                c.getLong(c.getColumnIndexOrThrow("added_at")),
                                c.getInt(c.getColumnIndexOrThrow("flags"))));
            }
        } finally {
            c.close();
        }
        return result;
    }

    // ---- x3dhpq DAO: committed_device (devicelist shrink guard) ----

    /**
     * Replaces the committed device-id set for {@code accountUuid} with {@code ids}:
     * the device ids of the most recently ACCEPTED (inbound, own list) or PUBLISHED
     * (outbound) authoritative devicelist. Deliberately independent of
     * x3dhpq_local_device / x3dhpq_co_account_device so publishDeviceList()'s
     * shrink guard is not circular.
     */
    public void putX3dhpqCommittedDevices(String accountUuid, java.util.Collection<Integer> ids) {
        final SQLiteDatabase db = getWritableDatabase();
        db.beginTransaction();
        try {
            db.delete("x3dhpq_committed_device", "account_uuid=?", new String[] {accountUuid});
            if (ids != null) {
                for (final Integer id : ids) {
                    final ContentValues v = new ContentValues();
                    v.put("account_uuid", accountUuid);
                    v.put("device_id", id);
                    db.insertWithOnConflict(
                            "x3dhpq_committed_device", null, v, SQLiteDatabase.CONFLICT_REPLACE);
                }
            }
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public java.util.Set<Integer> loadX3dhpqCommittedDeviceIds(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_committed_device",
                        new String[] {"device_id"},
                        "account_uuid=?",
                        new String[] {accountUuid},
                        null,
                        null,
                        null);
        final java.util.Set<Integer> result = new java.util.HashSet<>();
        try {
            while (c.moveToNext()) {
                result.add(c.getInt(c.getColumnIndexOrThrow("device_id")));
            }
        } finally {
            c.close();
        }
        return result;
    }

    // ---- x3dhpq DAO: device_audit (§11.7 device-authorization DAG) ----

    /**
     * Persists a device-audit DAG entry (dedup key: entry_hash_hex). Idempotent —
     * re-ingesting the same entry (e.g. re-running the genesis-bootstrap check) is a
     * silent no-op via CONFLICT_IGNORE, mirroring DeviceDag#ingest's own
     * content-hash dedup semantics.
     */
    public void putX3dhpqDeviceAuditEntry(
            String accountUuid, String entryHashHex, byte[] entryBlob, long createdAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("entry_hash_hex", entryHashHex);
        v.put("entry_blob", entryBlob);
        v.put("created_at", createdAt);
        db.insertWithOnConflict(
                "x3dhpq_device_audit", null, v, SQLiteDatabase.CONFLICT_IGNORE);
    }

    /** All device-audit entries for {@code accountUuid}, oldest first (insertion order is not
     * authorization order — callers must run DeviceDag's own canonical-order fold). */
    public List<X3dhpqDeviceAuditEntryRow> listX3dhpqDeviceAuditEntries(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_device_audit",
                        null,
                        "account_uuid=?",
                        new String[] {accountUuid},
                        null,
                        null,
                        "created_at ASC");
        final List<X3dhpqDeviceAuditEntryRow> result = new ArrayList<>();
        try {
            while (c.moveToNext()) {
                result.add(
                        new X3dhpqDeviceAuditEntryRow(
                                c.getString(c.getColumnIndexOrThrow("account_uuid")),
                                c.getString(c.getColumnIndexOrThrow("entry_hash_hex")),
                                c.getBlob(c.getColumnIndexOrThrow("entry_blob")),
                                c.getLong(c.getColumnIndexOrThrow("created_at"))));
            }
        } finally {
            c.close();
        }
        return result;
    }

    // ---- x3dhpq DAO: signed_pre_key ----

    public void putX3dhpqSignedPreKey(
            String accountUuid,
            int keyId,
            byte[] pubX,
            byte[] privX,
            byte[] sigEd,
            byte[] sigMldsa,
            long createdAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("key_id", keyId);
        v.put("public_x25519", pubX);
        v.put("private_x25519", x3dhpqWrap(privX));
        v.put("signature_ed25519", sigEd);
        v.put("signature_mldsa", sigMldsa);
        v.put("created_at", createdAt);
        db.insertWithOnConflict(
                "x3dhpq_signed_pre_key", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqSignedPreKeyRow loadX3dhpqSignedPreKey(String accountUuid, int keyId) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_signed_pre_key",
                        null,
                        "account_uuid=? AND key_id=?",
                        new String[] {accountUuid, Integer.toString(keyId)},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return x3dhpqSignedPreKeyFromCursor(c);
        } finally {
            c.close();
        }
    }

    public X3dhpqSignedPreKeyRow loadLatestX3dhpqSignedPreKey(String accountUuid) {
        // most recently created signed pre key for this account
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_signed_pre_key",
                        null,
                        "account_uuid=?",
                        new String[] {accountUuid},
                        null,
                        null,
                        "created_at DESC",
                        "1");
        try {
            if (!c.moveToFirst()) return null;
            return x3dhpqSignedPreKeyFromCursor(c);
        } finally {
            c.close();
        }
    }

    private X3dhpqSignedPreKeyRow x3dhpqSignedPreKeyFromCursor(Cursor c) {
        return new X3dhpqSignedPreKeyRow(
                c.getString(c.getColumnIndexOrThrow("account_uuid")),
                c.getInt(c.getColumnIndexOrThrow("key_id")),
                c.getBlob(c.getColumnIndexOrThrow("public_x25519")),
                x3dhpqUnwrap(c.getBlob(c.getColumnIndexOrThrow("private_x25519"))),
                c.getBlob(c.getColumnIndexOrThrow("signature_ed25519")),
                c.getBlob(c.getColumnIndexOrThrow("signature_mldsa")),
                c.getLong(c.getColumnIndexOrThrow("created_at")));
    }

    // ---- x3dhpq DAO: kem_pre_key ----

    public void putX3dhpqKemPreKey(
            String accountUuid, int keyId, byte[] pub, byte[] priv,
            byte[] sigEd25519, byte[] sigMldsa) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("key_id", keyId);
        v.put("public_key", pub);
        v.put("private_key", x3dhpqWrap(priv));
        v.put("sig_ed25519", sigEd25519);
        v.put("sig_mldsa", sigMldsa);
        db.insertWithOnConflict(
                "x3dhpq_kem_pre_key", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqKemPreKeyRow loadX3dhpqKemPreKey(String accountUuid, int keyId) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_kem_pre_key",
                        null,
                        "account_uuid=? AND key_id=?",
                        new String[] {accountUuid, Integer.toString(keyId)},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqKemPreKeyRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getInt(c.getColumnIndexOrThrow("key_id")),
                    c.getBlob(c.getColumnIndexOrThrow("public_key")),
                    x3dhpqUnwrap(c.getBlob(c.getColumnIndexOrThrow("private_key"))),
                    c.getBlob(c.getColumnIndexOrThrow("sig_ed25519")),
                    c.getBlob(c.getColumnIndexOrThrow("sig_mldsa")));
        } finally {
            c.close();
        }
    }

    public List<Integer> listX3dhpqKemPreKeyIds(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_kem_pre_key",
                        new String[] {"key_id"},
                        "account_uuid=?",
                        new String[] {accountUuid},
                        null,
                        null,
                        null);
        final List<Integer> ids = new ArrayList<>();
        try {
            while (c.moveToNext()) ids.add(c.getInt(0));
        } finally {
            c.close();
        }
        return ids;
    }

    // ---- x3dhpq DAO: one_time_pre_key ----

    public void putX3dhpqOneTimePreKey(
            String accountUuid, int keyId, byte[] pubX, byte[] privX) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("key_id", keyId);
        v.put("public_x25519", pubX);
        v.put("private_x25519", x3dhpqWrap(privX));
        v.put("consumed", 0);
        db.insertWithOnConflict(
                "x3dhpq_one_time_pre_key", null, v, SQLiteDatabase.CONFLICT_IGNORE);
    }

    public X3dhpqOneTimePreKeyRow loadX3dhpqOneTimePreKey(String accountUuid, int keyId) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_one_time_pre_key",
                        null,
                        "account_uuid=? AND key_id=?",
                        new String[] {accountUuid, Integer.toString(keyId)},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqOneTimePreKeyRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getInt(c.getColumnIndexOrThrow("key_id")),
                    c.getBlob(c.getColumnIndexOrThrow("public_x25519")),
                    x3dhpqUnwrap(c.getBlob(c.getColumnIndexOrThrow("private_x25519"))),
                    c.getInt(c.getColumnIndexOrThrow("consumed")) != 0);
        } finally {
            c.close();
        }
    }

    public void markX3dhpqOneTimePreKeyConsumed(String accountUuid, int keyId) {
        // flag key so it is not re-issued; Wave D physically deletes after session confirm
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("consumed", 1);
        db.update(
                "x3dhpq_one_time_pre_key",
                v,
                "account_uuid=? AND key_id=?",
                new String[] {accountUuid, Integer.toString(keyId)});
    }

    public List<Integer> listX3dhpqUnusedOneTimePreKeyIds(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_one_time_pre_key",
                        new String[] {"key_id"},
                        "account_uuid=? AND consumed=0",
                        new String[] {accountUuid},
                        null,
                        null,
                        null);
        final List<Integer> ids = new ArrayList<>();
        try {
            while (c.moveToNext()) ids.add(c.getInt(0));
        } finally {
            c.close();
        }
        return ids;
    }

    // ---- x3dhpq DAO: remote_device ----

    public void putX3dhpqRemoteDevice(
            String accountUuid,
            String peerJid,
            int deviceId,
            byte[] certMarshal,
            Long lastSeen) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("peer_jid", peerJid);
        v.put("device_id", deviceId);
        v.put("cert_marshal", certMarshal);
        if (lastSeen != null) v.put("last_seen", lastSeen);
        else v.putNull("last_seen");
        db.insertWithOnConflict(
                "x3dhpq_remote_device", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqRemoteDeviceRow loadX3dhpqRemoteDevice(
            String accountUuid, String peerJid, int deviceId) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_remote_device",
                        null,
                        "account_uuid=? AND peer_jid=? AND device_id=?",
                        new String[] {accountUuid, peerJid, Integer.toString(deviceId)},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            final int lastSeenIdx = c.getColumnIndexOrThrow("last_seen");
            final Long lastSeen = c.isNull(lastSeenIdx) ? null : c.getLong(lastSeenIdx);
            return new X3dhpqRemoteDeviceRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getString(c.getColumnIndexOrThrow("peer_jid")),
                    c.getInt(c.getColumnIndexOrThrow("device_id")),
                    c.getBlob(c.getColumnIndexOrThrow("cert_marshal")),
                    lastSeen);
        } finally {
            c.close();
        }
    }

    public List<X3dhpqRemoteDeviceRow> listX3dhpqRemoteDevices(
            String accountUuid, String peerJid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_remote_device",
                        null,
                        "account_uuid=? AND peer_jid=?",
                        new String[] {accountUuid, peerJid},
                        null,
                        null,
                        null);
        final List<X3dhpqRemoteDeviceRow> result = new ArrayList<>();
        try {
            while (c.moveToNext()) {
                final int lastSeenIdx = c.getColumnIndexOrThrow("last_seen");
                final Long lastSeen = c.isNull(lastSeenIdx) ? null : c.getLong(lastSeenIdx);
                result.add(
                        new X3dhpqRemoteDeviceRow(
                                c.getString(c.getColumnIndexOrThrow("account_uuid")),
                                c.getString(c.getColumnIndexOrThrow("peer_jid")),
                                c.getInt(c.getColumnIndexOrThrow("device_id")),
                                c.getBlob(c.getColumnIndexOrThrow("cert_marshal")),
                                lastSeen));
            }
        } finally {
            c.close();
        }
        return result;
    }

    /**
     * Wipe every x3dhpq_session row for the given account. Used as a one-shot
     * recovery mechanism when the on-disk session blob format is known to
     * disagree with the on-wire ratchet expectations of remote peers (e.g.
     * a session bootstrapped before the initiator/responder pre-ratchet fix
     * lands). All paired peers will re-establish on the next outgoing send.
     */
    public int wipeAllX3dhpqSessions(String accountUuid) {
        final SQLiteDatabase db = getWritableDatabase();
        return db.delete("x3dhpq_session", "account_uuid=?", new String[] {accountUuid});
    }

    /**
     * Drop every cached row for {@code (accountUuid, peerJid)} whose deviceId
     * is NOT in {@code keepIds}. Called after a fresh devicelist arrives so
     * stale device entries (from a peer that regenerated its keys) don't
     * silently keep getting pairwise envelopes addressed to ghost devices.
     * Also cascades into x3dhpq_remote_bundle and x3dhpq_session for the
     * dropped device ids.
     */
    public void pruneX3dhpqRemoteDevicesNotIn(
            String accountUuid, String peerJid, java.util.Collection<Integer> keepIds) {
        final SQLiteDatabase db = getWritableDatabase();
        // Build "id NOT IN (?, ?, ...)" — empty keepIds means "drop all rows
        // for this peer".
        if (keepIds == null || keepIds.isEmpty()) {
            db.delete("x3dhpq_remote_device",
                    "account_uuid=? AND peer_jid=?",
                    new String[] {accountUuid, peerJid});
            db.delete("x3dhpq_remote_bundle",
                    "account_uuid=? AND peer_jid=?",
                    new String[] {accountUuid, peerJid});
            db.delete("x3dhpq_session",
                    "account_uuid=? AND peer_jid=?",
                    new String[] {accountUuid, peerJid});
            return;
        }
        final StringBuilder placeholders = new StringBuilder();
        final String[] args = new String[keepIds.size() + 2];
        args[0] = accountUuid;
        args[1] = peerJid;
        int i = 2;
        for (Integer id : keepIds) {
            if (placeholders.length() > 0) placeholders.append(',');
            placeholders.append('?');
            args[i++] = Integer.toString(id);
        }
        final String where = "account_uuid=? AND peer_jid=? AND device_id NOT IN (" + placeholders + ")";
        db.delete("x3dhpq_remote_device", where, args);
        db.delete("x3dhpq_remote_bundle", where, args);
        db.delete("x3dhpq_session", where, args);
    }

    /** List all remote device rows for an account (all peers). Used by GroupCryptoService for AIK fp → JID lookup. */
    public List<X3dhpqRemoteDeviceRow> listAllX3dhpqRemoteDevices(String accountUuid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c = db.query(
                "x3dhpq_remote_device",
                null,
                "account_uuid=?",
                new String[]{accountUuid},
                null, null, null);
        final List<X3dhpqRemoteDeviceRow> result = new ArrayList<>();
        try {
            while (c.moveToNext()) {
                final int lastSeenIdx = c.getColumnIndexOrThrow("last_seen");
                final Long lastSeen = c.isNull(lastSeenIdx) ? null : c.getLong(lastSeenIdx);
                result.add(new X3dhpqRemoteDeviceRow(
                        c.getString(c.getColumnIndexOrThrow("account_uuid")),
                        c.getString(c.getColumnIndexOrThrow("peer_jid")),
                        c.getInt(c.getColumnIndexOrThrow("device_id")),
                        c.getBlob(c.getColumnIndexOrThrow("cert_marshal")),
                        lastSeen));
            }
        } finally {
            c.close();
        }
        return result;
    }

    // ---- x3dhpq DAO: remote_bundle ----

    public void putX3dhpqRemoteBundle(
            String accountUuid,
            String peerJid,
            int deviceId,
            byte[] aikPubMarshal,
            byte[] bundleXml,
            long fetchedAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("peer_jid", peerJid);
        v.put("device_id", deviceId);
        v.put("aik_pub_marshal", aikPubMarshal);
        v.put("bundle_xml", bundleXml);
        v.put("fetched_at", fetchedAt);
        db.insertWithOnConflict(
                "x3dhpq_remote_bundle", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqRemoteBundleRow loadX3dhpqRemoteBundle(
            String accountUuid, String peerJid, int deviceId) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_remote_bundle",
                        null,
                        "account_uuid=? AND peer_jid=? AND device_id=?",
                        new String[] {accountUuid, peerJid, Integer.toString(deviceId)},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqRemoteBundleRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getString(c.getColumnIndexOrThrow("peer_jid")),
                    c.getInt(c.getColumnIndexOrThrow("device_id")),
                    c.getBlob(c.getColumnIndexOrThrow("aik_pub_marshal")),
                    c.getBlob(c.getColumnIndexOrThrow("bundle_xml")),
                    c.getLong(c.getColumnIndexOrThrow("fetched_at")));
        } finally {
            c.close();
        }
    }

    // ---- x3dhpq DAO: session ----

    public void putX3dhpqSession(
            String accountUuid,
            String peerJid,
            int deviceId,
            byte[] stateBlob,
            long updatedAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("peer_jid", peerJid);
        v.put("device_id", deviceId);
        v.put("state_blob", x3dhpqWrap(stateBlob));
        v.put("updated_at", updatedAt);
        db.insertWithOnConflict(
                "x3dhpq_session", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqSessionRow loadX3dhpqSession(
            String accountUuid, String peerJid, int deviceId) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_session",
                        null,
                        "account_uuid=? AND peer_jid=? AND device_id=?",
                        new String[] {accountUuid, peerJid, Integer.toString(deviceId)},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return x3dhpqSessionFromCursor(c);
        } finally {
            c.close();
        }
    }

    public List<X3dhpqSessionRow> listX3dhpqSessionsForPeer(
            String accountUuid, String peerJid) {
        // uses x3dhpq_session_peer index for fast per-peer lookup
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_session",
                        null,
                        "account_uuid=? AND peer_jid=?",
                        new String[] {accountUuid, peerJid},
                        null,
                        null,
                        null);
        final List<X3dhpqSessionRow> result = new ArrayList<>();
        try {
            while (c.moveToNext()) result.add(x3dhpqSessionFromCursor(c));
        } finally {
            c.close();
        }
        return result;
    }

    private X3dhpqSessionRow x3dhpqSessionFromCursor(Cursor c) {
        return new X3dhpqSessionRow(
                c.getString(c.getColumnIndexOrThrow("account_uuid")),
                c.getString(c.getColumnIndexOrThrow("peer_jid")),
                c.getInt(c.getColumnIndexOrThrow("device_id")),
                x3dhpqUnwrap(c.getBlob(c.getColumnIndexOrThrow("state_blob"))),
                c.getLong(c.getColumnIndexOrThrow("updated_at")));
    }

    // ---- x3dhpq DAO: group_session ----

    public void putX3dhpqGroupSession(
            String accountUuid,
            String roomJid,
            long epoch,
            byte[] stateBlob,
            long updatedAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("room_jid", roomJid);
        v.put("epoch", epoch);
        v.put("state_blob", x3dhpqWrap(stateBlob));
        v.put("updated_at", updatedAt);
        db.insertWithOnConflict(
                "x3dhpq_group_session", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqGroupSessionRow loadX3dhpqGroupSession(String accountUuid, String roomJid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_group_session",
                        null,
                        "account_uuid=? AND room_jid=?",
                        new String[] {accountUuid, roomJid},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqGroupSessionRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getString(c.getColumnIndexOrThrow("room_jid")),
                    c.getLong(c.getColumnIndexOrThrow("epoch")),
                    x3dhpqUnwrap(c.getBlob(c.getColumnIndexOrThrow("state_blob"))),
                    c.getLong(c.getColumnIndexOrThrow("updated_at")));
        } finally {
            c.close();
        }
    }

    // ---- x3dhpq DAO: group_membership ----

    public void putX3dhpqGroupMembership(
            String accountUuid,
            String roomJid,
            byte[] journalBlob,
            String itemId,
            long fetchedAt) {
        putX3dhpqGroupMembershipEntry(accountUuid, roomJid, itemId, journalBlob, itemId, fetchedAt);
    }

    public void putX3dhpqGroupMembershipEntry(
            String accountUuid,
            String roomJid,
            String entryHash,
            byte[] journalBlob,
            String itemId,
            long fetchedAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("account_uuid", accountUuid);
        v.put("room_jid", roomJid);
        v.put("entry_hash", entryHash);
        v.put("journal_blob", journalBlob);
        v.put("item_id", itemId);
        v.put("fetched_at", fetchedAt);
        db.insertWithOnConflict(
                "x3dhpq_group_membership", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    public X3dhpqGroupMembershipRow loadX3dhpqGroupMembership(
            String accountUuid, String roomJid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_group_membership",
                        null,
                        "account_uuid=? AND room_jid=?",
                        new String[] {accountUuid, roomJid},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return new X3dhpqGroupMembershipRow(
                    c.getString(c.getColumnIndexOrThrow("account_uuid")),
                    c.getString(c.getColumnIndexOrThrow("room_jid")),
                    c.getString(c.getColumnIndexOrThrow("entry_hash")),
                    c.getBlob(c.getColumnIndexOrThrow("journal_blob")),
                    c.getString(c.getColumnIndexOrThrow("item_id")),
                    c.getLong(c.getColumnIndexOrThrow("fetched_at")));
        } finally {
            c.close();
        }
    }

    public List<X3dhpqGroupMembershipRow> listX3dhpqGroupMembershipEntries(
            String accountUuid, String roomJid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_group_membership",
                        null,
                        "account_uuid=? AND room_jid=?",
                        new String[] {accountUuid, roomJid},
                        null,
                        null,
                        "fetched_at ASC, entry_hash ASC");
        final List<X3dhpqGroupMembershipRow> result = new ArrayList<>();
        try {
            while (c.moveToNext()) {
                result.add(new X3dhpqGroupMembershipRow(
                        c.getString(c.getColumnIndexOrThrow("account_uuid")),
                        c.getString(c.getColumnIndexOrThrow("room_jid")),
                        c.getString(c.getColumnIndexOrThrow("entry_hash")),
                        c.getBlob(c.getColumnIndexOrThrow("journal_blob")),
                        c.getString(c.getColumnIndexOrThrow("item_id")),
                        c.getLong(c.getColumnIndexOrThrow("fetched_at"))));
            }
        } finally {
            c.close();
        }
        return result;
    }

    // ---- x3dhpq DAO: pairing_session ----

    @Override
    public void putX3dhpqPairingSession(
            String accountUuid,
            byte[] sid,
            int role,
            String peerJid,
            String code,
            byte[] stateBlob,
            long expiresAt) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("sid", sid);
        v.put("account_uuid", accountUuid);
        v.put("role", role);
        v.put("peer_jid", peerJid);
        v.put("code", code);
        v.put("state_blob", x3dhpqWrap(stateBlob));
        v.put("expires_at", expiresAt);
        db.insertWithOnConflict(
                "x3dhpq_pairing_session", null, v, SQLiteDatabase.CONFLICT_REPLACE);
    }

    @Override
    public X3dhpqPairingSessionRow loadX3dhpqPairingSession(byte[] sid) {
        final SQLiteDatabase db = getReadableDatabase();
        final Cursor c =
                db.query(
                        "x3dhpq_pairing_session",
                        null,
                        "hex(sid)=?",
                        new String[] {CryptoHelper.bytesToHex(sid).toUpperCase()},
                        null,
                        null,
                        null);
        try {
            if (!c.moveToFirst()) return null;
            return x3dhpqPairingSessionFromCursor(c);
        } finally {
            c.close();
        }
    }

    @Override
    public void updateX3dhpqPairingState(byte[] sid, byte[] stateBlob) {
        final SQLiteDatabase db = getWritableDatabase();
        final ContentValues v = new ContentValues();
        v.put("state_blob", x3dhpqWrap(stateBlob));
        db.update(
                "x3dhpq_pairing_session",
                v,
                "hex(sid)=?",
                new String[] {CryptoHelper.bytesToHex(sid).toUpperCase()});
    }

    @Override
    public void deleteX3dhpqPairingSession(byte[] sid) {
        final SQLiteDatabase db = getWritableDatabase();
        db.delete(
                "x3dhpq_pairing_session",
                "hex(sid)=?",
                new String[] {CryptoHelper.bytesToHex(sid).toUpperCase()});
    }

    @Override
    public int sweepExpiredX3dhpqPairingSessions(long nowUnixSeconds) {
        final SQLiteDatabase db = getWritableDatabase();
        return db.delete(
                "x3dhpq_pairing_session",
                "expires_at < ?",
                new String[] {Long.toString(nowUnixSeconds)});
    }

    private X3dhpqPairingSessionRow x3dhpqPairingSessionFromCursor(Cursor c) {
        return new X3dhpqPairingSessionRow(
                c.getBlob(c.getColumnIndexOrThrow("sid")),
                c.getString(c.getColumnIndexOrThrow("account_uuid")),
                c.getInt(c.getColumnIndexOrThrow("role")),
                c.getString(c.getColumnIndexOrThrow("peer_jid")),
                c.getString(c.getColumnIndexOrThrow("code")),
                x3dhpqUnwrap(c.getBlob(c.getColumnIndexOrThrow("state_blob"))),
                c.getLong(c.getColumnIndexOrThrow("expires_at")));
    }

}
