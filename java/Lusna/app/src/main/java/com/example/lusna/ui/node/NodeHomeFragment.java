package com.example.lusna.ui.node;

import android.graphics.Typeface;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;

import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import com.example.lusna.R;
import com.lusna.ffi.deser.KernelResponseType;
import com.lusna.ffi.deser.domain.PeerList;
import com.lusna.ffi.outbound.FFIPacket;
import com.lusna.ffi.outbound.ToFFI;
import com.lusna.svc.LusnaService;

import static com.lusna.ffi.outbound.FFIPacket.STD_COMMAND;

public class NodeHomeFragment extends Fragment {

    protected String username;
    private PeerList peerList;

    private final TableRow.LayoutParams layoutParams = new TableRow.LayoutParams(TableLayout.LayoutParams.MATCH_PARENT, TableLayout.LayoutParams.WRAP_CONTENT);
    public NodeHomeFragment(String username) {
        this.username = username;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        ConstraintLayout lyt = view.findViewById(R.id.frameLayout2);
        TableLayout clientsTable = lyt.findViewById(R.id.clientsTable);
        FragmentManager fragmentManager = getParentFragmentManager();
        FragmentTransaction fragmentTransaction = fragmentManager.beginTransaction();
        fragmentTransaction.add(R.id.clientsTable, new NodeMessagesFragment(peerList));
        fragmentTransaction.commit();
        /*
        // assemble the table
        TableRow title = new TableRow(this.getContext());
        TextView cidTitle = new TextView(this.getContext());
        cidTitle.setText("Client ID");
        cidTitle.setTypeface(null, Typeface.BOLD);
        cidTitle.setGravity(Gravity.CENTER);

        TextView isOnlineTitle = new TextView(this.getContext());
        isOnlineTitle.setText("Status");
        isOnlineTitle.setTypeface(null, Typeface.BOLD);
        isOnlineTitle.setGravity(Gravity.CENTER);
        title.addView(cidTitle);
        title.addView(isOnlineTitle);

        ConstraintLayout lyt = view.findViewById(R.id.frameLayout2);
        TableLayout clientsTable = lyt.findViewById(R.id.clientsTable);

        if (clientsTable != null) {

        }*/
    }

    private View view;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        this.view = inflater.inflate(R.layout.fragment_node_home, container, false);
        return view;
    }
}