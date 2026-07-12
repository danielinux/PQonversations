package eu.siacs.conversations.crypto.x3dhpq;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Single source of truth for the purely-local, never-published device labels (§10.6
 * client-side label). Each device defaults to a friendly {@code "Device N"} ordinal
 * (1-based, assigned over the account's associated devices sorted ascending by unsigned
 * id so it is deterministic and shared across UI surfaces) and can be given a local
 * nickname stored only on this device in a private {@link SharedPreferences} file, keyed
 * by {@code accountUuid:deviceId}. The nickname is never signed or transmitted.
 *
 * <p>Used both by the device-management screen (X3dhpqSelfDevicesActivity) and by the
 * message list, so that a sibling-authored (own-carbon/MAM) message can be attributed to
 * the exact same label the user sees and renames in the devices screen.
 */
public final class X3dhpqDeviceLabels {

    private static final String NICKNAME_PREFS = "x3dhpq_device_nicknames";

    private X3dhpqDeviceLabels() {}

    private static SharedPreferences prefs(final Context context) {
        return context.getSharedPreferences(NICKNAME_PREFS, Context.MODE_PRIVATE);
    }

    public static String nicknameKey(final String accountUuid, final int deviceId) {
        return accountUuid + ":" + Integer.toUnsignedString(deviceId);
    }

    /** The user's local nickname for a device, or {@code null} if none is set. */
    public static String getNickname(
            final Context context, final String accountUuid, final int deviceId) {
        final String n = prefs(context).getString(nicknameKey(accountUuid, deviceId), null);
        return (n != null && !n.trim().isEmpty()) ? n : null;
    }

    /** Store (or, for a blank name, clear back to the default) a device's local nickname. */
    public static void setNickname(
            final Context context,
            final String accountUuid,
            final int deviceId,
            final String name) {
        final SharedPreferences prefs = prefs(context);
        if (name == null || name.trim().isEmpty()) {
            prefs.edit().remove(nicknameKey(accountUuid, deviceId)).apply();
        } else {
            prefs.edit().putString(nicknameKey(accountUuid, deviceId), name.trim()).apply();
        }
    }

    /**
     * 1-based "Device N" ordinal for {@code deviceId} over {@code allDeviceIds}, sorted
     * ascending (unsigned). Returns 0 when the device is not present in the set.
     */
    public static int ordinal(final List<Integer> allDeviceIds, final int deviceId) {
        final List<Integer> ids = new ArrayList<>(allDeviceIds);
        Collections.sort(ids, Integer::compareUnsigned);
        int n = 1;
        for (final Integer id : ids) {
            if (id != null && id == deviceId) {
                return n;
            }
            n++;
        }
        return 0;
    }

    /**
     * The display name for a device: its local nickname if set, otherwise the default
     * "Device N" ordinal computed over {@code allDeviceIds}. Falls back to the raw
     * unsigned id if the device is not present in the given set.
     */
    public static String displayName(
            final Context context,
            final String accountUuid,
            final int deviceId,
            final List<Integer> allDeviceIds) {
        final String nick = getNickname(context, accountUuid, deviceId);
        if (nick != null) {
            return nick;
        }
        final int ord = ordinal(allDeviceIds, deviceId);
        return "Device " + (ord > 0 ? ord : Integer.toUnsignedString(deviceId));
    }
}
