package eu.siacs.conversations.crypto.x3dhpq;

import android.util.Log;
import eu.siacs.conversations.Config;
import im.conversations.x3dhpq.crypto.X3dhpqCrypto;
import im.conversations.x3dhpq.types.AccountIdentityPub;
import im.conversations.x3dhpq.types.AuditEntry;
import im.conversations.x3dhpq.types.Blake2b160;
import im.conversations.x3dhpq.types.GroupMember;
import im.conversations.x3dhpq.types.Sha256;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses and verifies the chain of {@code <membership-entry>} items from the
 * room's {@code urn:xmppqr:x3dhpq:group:0} PEP node.
 *
 * Each entry must be a signed {@code AuditEntry} (action=AddMember=5 or RemoveMember=6).
 * The entry payload is: {@code <aik_fp 20 bytes> | <epoch_after uint32 BE>}.
 *
 * Verification uses the room owner's AIK (Ed25519 + ML-DSA-65 hybrid).
 * Chain verification: prevHash of entry[i] == SHA-256(marshal(entry[i-1])).
 */
public final class MembershipJournal {

    private static final String TAG = "MembershipJournal";

    private final Blake2b160 blake = X3dhpqCrypto.BLAKE2B_160;
    private final Sha256 sha256 = X3dhpqCrypto.SHA256;

    // Ordered list of verified entries (by seq).
    private final List<AuditEntry> entries = new ArrayList<>();

    // Current member set: AIK fingerprint → AccountIdentityPub
    private final Map<String, AccountIdentityPub> members = new LinkedHashMap<>();

    // Members removed: AIK fingerprint → epoch at removal
    private final Map<String, Long> removedAiks = new HashMap<>();

    // Hash of the last appended entry's marshal(); null before first entry.
    private byte[] lastHash = null;

    // Highest seq processed.
    private long lastSeq = -1;

    // Epoch derived authoritatively from journal replay (§13.1a/§13.5): the
    // genesis entry establishes epoch 0 (no rotation); every subsequent entry
    // rotates exactly once. -1 before the first entry.
    private long derivedEpoch = -1;

    // Owner AIK (set on first entry for TOFU, or pre-set by caller).
    private AccountIdentityPub ownerAik;

    // Member AIK pub objects, keyed by fingerprint, for group session population.
    private final Map<String, AccountIdentityPub> knownAikPubs = new HashMap<>();

    public MembershipJournal() {}

    /**
     * Pre-set the expected room owner AIK (e.g. from a verified pinned value).
     * If null, the journal uses TOFU from the first appended entry.
     */
    public void setOwnerAik(AccountIdentityPub aik) {
        this.ownerAik = aik;
    }

    public AccountIdentityPub getOwnerAik() {
        return ownerAik;
    }

    /**
     * Append and verify a marshalled AuditEntry.
     * Throws {@link IllegalArgumentException} on any verification failure.
     *
     * @param entryBytes raw bytes from the membership-entry PEP item
     * @param memberAiks map from AIK fingerprint to AccountIdentityPub for the members
     *                   referenced by this entry's aik_fp field (needed to build the
     *                   member set). May be empty; unknown AIKs are tracked by fp only.
     */
    public void append(byte[] entryBytes, Map<String, AccountIdentityPub> memberAiks) {
        if (entryBytes == null || entryBytes.length < 10) {
            throw new IllegalArgumentException("MembershipJournal: null or too-short entry");
        }

        final AuditEntry entry = AuditEntry.unmarshal(entryBytes);

        // Verify action is AddMember or RemoveMember
        if (entry.getAction() != AuditEntry.ACTION_ADD_MEMBER
                && entry.getAction() != AuditEntry.ACTION_REMOVE_MEMBER) {
            throw new IllegalArgumentException(
                    "MembershipJournal: unexpected action " + entry.getAction());
        }

        // Sequence must be lastSeq+1
        long expectedSeq = lastSeq + 1;
        if (entry.getSeq() != expectedSeq) {
            throw new IllegalArgumentException(
                    "MembershipJournal: seq gap: expected " + expectedSeq
                            + " got " + entry.getSeq());
        }

        // Chain link: prevHash must be zero (genesis) or SHA-256 of previous marshal
        byte[] prevHash = entry.getPrevHash();
        if (expectedSeq == 0) {
            // Genesis: prevHash must be all-zero
            for (byte b : prevHash) {
                if (b != 0) {
                    throw new IllegalArgumentException("MembershipJournal: genesis entry has non-zero prevHash");
                }
            }
        } else {
            if (lastHash == null || !Arrays.equals(prevHash, lastHash)) {
                throw new IllegalArgumentException("MembershipJournal: chain link broken at seq " + entry.getSeq());
            }
        }

        // Determine owner AIK for signature verification
        // TOFU: the first entry's signature must self-consistently verify.
        // We need the owner's AIK to be known from an out-of-band source or from the
        // first AddMember entry that adds the owner themselves. In TOFU mode, we
        // extract it from the member that is being added in entry 0.
        if (ownerAik == null) {
            // TOFU: look up the AIK from the provided map using the entry's aik_fp field.
            byte[][] parsed = AuditEntry.parseMemberPayload(entry.getPayload());
            String fp = fingerprintHex(parsed[0]);
            AccountIdentityPub aik = memberAiks != null ? memberAiks.get(fp) : null;
            if (aik == null) {
                throw new IllegalArgumentException(
                        "MembershipJournal: TOFU bootstrap requires AIK for fp=" + fp);
            }
            ownerAik = aik;
        }

        // Verify signatures
        byte[] signedPart = entry.signedPart();
        boolean edOk = X3dhpqCrypto.ed25519Verify(
                ownerAik.getPubEd25519(), signedPart, entry.getSigEd25519());
        boolean mlOk = X3dhpqCrypto.mldsa65Verify(
                ownerAik.getPubMLDSA(), signedPart, entry.getSigMLDSA());
        if (!edOk || !mlOk) {
            throw new IllegalArgumentException(
                    "MembershipJournal: signature verification failed at seq " + entry.getSeq()
                            + " (ed=" + edOk + " mldsa=" + mlOk + ")");
        }

        // Process payload
        byte[][] memberPayload = AuditEntry.parseMemberPayload(entry.getPayload());
        byte[] aikFp20 = memberPayload[0];
        long epochAfter = ByteBuffer.wrap(memberPayload[1]).order(ByteOrder.BIG_ENDIAN).getInt() & 0xFFFFFFFFL;
        String fpHex = fingerprintHex(aikFp20);

        // SHOULD-level cross-check (§13.1a): derive the epoch authoritatively
        // from replay (genesis => 0, every later entry => previous + 1) and
        // compare it to the writer-supplied epoch_after. A mismatch signals a
        // non-conforming writer or a forked journal; warn but do NOT reject, so
        // interop stays robust against clients that once hardcoded the value.
        final long derivedEpochForThis = (expectedSeq == 0) ? 0 : (derivedEpoch + 1);
        if (epochAfter != derivedEpochForThis) {
            Log.w(Config.LOGTAG, TAG + ": epoch_after mismatch at seq=" + entry.getSeq()
                    + " — writer wrote " + epochAfter + " but replay derives "
                    + derivedEpochForThis + " (accepting; see §13.1a)");
        }
        derivedEpoch = derivedEpochForThis;

        if (memberAiks != null && memberAiks.containsKey(fpHex)) {
            knownAikPubs.put(fpHex, memberAiks.get(fpHex));
        }

        if (entry.getAction() == AuditEntry.ACTION_ADD_MEMBER) {
            AccountIdentityPub aik = knownAikPubs.get(fpHex);
            if (aik != null) {
                members.put(fpHex, aik);
            } else {
                // Store fingerprint only if AIK pub not provided
                Log.d(Config.LOGTAG, TAG + ": AddMember seq=" + entry.getSeq()
                        + " fp=" + fpHex + " (AIK pub not provided)");
                // Mark as known-fp member (put null aik as placeholder)
                members.put(fpHex, null);
            }
            removedAiks.remove(fpHex);
        } else { // ACTION_REMOVE_MEMBER
            members.remove(fpHex);
            removedAiks.put(fpHex, epochAfter);
        }

        // Update chain state
        lastHash = sha256.hash(entryBytes);
        lastSeq = entry.getSeq();
        entries.add(entry);
    }

    /**
     * Returns a read-only view of the current member map (AIK fp → AIK pub, may contain nulls).
     */
    public Map<String, AccountIdentityPub> getMembers() {
        return Collections.unmodifiableMap(members);
    }

    /**
     * Returns a read-only view of the removed AIKs map (AIK fp → epoch at removal).
     */
    public Map<String, Long> getRemovedAiks() {
        return Collections.unmodifiableMap(removedAiks);
    }

    /** Returns true if aikFp is in the current member set. */
    public boolean isMember(String aikFp) {
        return members.containsKey(aikFp);
    }

    /** Returns true if aikFp has been removed. */
    public boolean isRemoved(String aikFp) {
        return removedAiks.containsKey(aikFp);
    }

    public long getLastSeq() {
        return lastSeq;
    }

    /** SHA-256 of the last entry's marshal(); null before any append. */
    public byte[] getLastHash() {
        return lastHash == null ? null : Arrays.copyOf(lastHash, lastHash.length);
    }

    /** Number of verified entries currently held. */
    public int size() {
        return entries.size();
    }

    /**
     * Build {@link GroupMember} objects from the current member set.
     * Members whose AIK pub is not known are omitted.
     */
    public List<GroupMember> buildGroupMembers() {
        List<GroupMember> result = new ArrayList<>();
        for (Map.Entry<String, AccountIdentityPub> e : members.entrySet()) {
            if (e.getValue() != null) {
                result.add(new GroupMember(e.getValue(), new ArrayList<>()));
            }
        }
        return result;
    }

    /** Encode the raw 20-byte fp as uppercase hex for use as map key. */
    public static String fingerprintHex(byte[] fp20) {
        StringBuilder sb = new StringBuilder(40);
        for (byte b : fp20) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }
}
