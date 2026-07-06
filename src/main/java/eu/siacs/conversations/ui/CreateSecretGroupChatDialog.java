package eu.siacs.conversations.ui;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.widget.AutoCompleteTextView;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.databinding.DataBindingUtil;
import androidx.fragment.app.DialogFragment;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import eu.siacs.conversations.R;
import eu.siacs.conversations.databinding.DialogCreateSecretGroupBinding;
import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.ui.util.DelayedHintHelper;
import eu.siacs.conversations.xmpp.XmppConnection;
import eu.siacs.conversations.xmpp.manager.MultiUserChatManager;
import java.util.ArrayList;
import java.util.List;

/**
 * Dedicated, first-class dialog for creating a "Secret Post-Quantum Group": a
 * members-only, non-anonymous, persistent MUC that is always protected by
 * x3dhpq end-to-end encryption and managed exclusively by its owner.
 *
 * <p>Before letting the user proceed it re-checks that the selected account's
 * conference/MUC service is available, so we never offer a creation that will
 * fail server-side.
 */
public class CreateSecretGroupChatDialog extends DialogFragment {

    private static final String ACCOUNTS_LIST_KEY = "activated_accounts_list";
    private CreateSecretGroupChatDialogListener mListener;

    public static CreateSecretGroupChatDialog newInstance(List<String> accounts) {
        CreateSecretGroupChatDialog dialog = new CreateSecretGroupChatDialog();
        Bundle bundle = new Bundle();
        bundle.putStringArrayList(ACCOUNTS_LIST_KEY, (ArrayList<String>) accounts);
        dialog.setArguments(bundle);
        return dialog;
    }

    /**
     * Server capability gate: an account can host a secret group only if its
     * MUC/conference service has been discovered. Mirrors the check that
     * {@link MultiUserChatManager#createPrivateGroupChat} performs, so we fail
     * early with a clear message rather than after the user picks participants.
     */
    public static boolean canCreateGroup(final Account account) {
        if (account == null) {
            return false;
        }
        final XmppConnection connection = account.getXmppConnection();
        if (connection == null) {
            return false;
        }
        return connection.getManager(MultiUserChatManager.class).getService() != null;
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        setRetainInstance(true);
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        final MaterialAlertDialogBuilder builder =
                new MaterialAlertDialogBuilder(requireActivity());
        builder.setTitle(R.string.create_secret_group_title);
        final DialogCreateSecretGroupBinding binding =
                DataBindingUtil.inflate(
                        getActivity().getLayoutInflater(),
                        R.layout.dialog_create_secret_group,
                        null,
                        false);
        ArrayList<String> mActivatedAccounts = getArguments().getStringArrayList(ACCOUNTS_LIST_KEY);
        StartConversationActivity.populateAccountSpinner(
                getActivity(), mActivatedAccounts, binding.account);
        builder.setView(binding.getRoot());
        builder.setPositiveButton(R.string.choose_participants, null);
        builder.setNegativeButton(R.string.cancel, null);
        DelayedHintHelper.setHint(R.string.providing_a_name_is_optional, binding.groupChatName);
        final AlertDialog dialog = builder.create();
        binding.groupChatName.setOnEditorActionListener(
                (v, actionId, event) -> {
                    submit(dialog, binding.account, binding.groupChatName.getText().toString());
                    return true;
                });
        dialog.setOnShowListener(
                dialogInterface ->
                        dialog.getButton(DialogInterface.BUTTON_POSITIVE)
                                .setOnClickListener(
                                        v ->
                                                submit(
                                                        dialog,
                                                        binding.account,
                                                        binding.groupChatName
                                                                .getText()
                                                                .toString())));
        return dialog;
    }

    private void submit(
            final AlertDialog dialog, final AutoCompleteTextView spinner, final String name) {
        final Account account = StartConversationActivity.getSelectedAccount(getActivity(), spinner);
        if (account == null) {
            return;
        }
        if (!canCreateGroup(account)) {
            Toast.makeText(getActivity(), R.string.secret_group_no_muc, Toast.LENGTH_LONG).show();
            return;
        }
        mListener.onCreateSecretGroupChat(spinner, name.trim());
        dialog.dismiss();
    }

    public interface CreateSecretGroupChatDialogListener {
        void onCreateSecretGroupChat(AutoCompleteTextView spinner, String subject);
    }

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        try {
            mListener = (CreateSecretGroupChatDialogListener) context;
        } catch (ClassCastException e) {
            throw new ClassCastException(
                    context + " must implement CreateSecretGroupChatDialogListener");
        }
    }

    @Override
    public void onDestroyView() {
        Dialog dialog = getDialog();
        if (dialog != null && getRetainInstance()) {
            dialog.setDismissMessage(null);
        }
        super.onDestroyView();
    }
}
