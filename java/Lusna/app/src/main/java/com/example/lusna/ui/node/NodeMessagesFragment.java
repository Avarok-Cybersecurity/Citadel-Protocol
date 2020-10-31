package com.example.lusna.ui.node;

import android.content.Context;
import android.os.Bundle;

import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.example.lusna.ui.node.adapter.MyContactRecyclerViewAdapter;
import com.example.lusna.R;
import com.example.lusna.dummy.DummyContent;
import com.lusna.ffi.deser.KernelResponseType;
import com.lusna.ffi.deser.domain.PeerList;
import com.lusna.ffi.outbound.FFIPacket;
import com.lusna.ffi.outbound.ToFFI;
import com.lusna.svc.LusnaService;

import java.util.Objects;

import static com.lusna.ffi.outbound.FFIPacket.STD_COMMAND;

/**
 * A fragment representing a list of Items.
 */
public class NodeMessagesFragment extends Fragment {

    // TODO: Customize parameter argument names
    private static final String ARG_COLUMN_COUNT = "column-count";
    // TODO: Customize parameters
    private int mColumnCount = 1;
    /**
     * Mandatory empty constructor for the fragment manager to instantiate the
     * fragment (e.g. upon screen orientation changes).
     */
    public NodeMessagesFragment() {

    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (getArguments() != null) {
            mColumnCount = getArguments().getInt(ARG_COLUMN_COUNT);
        }
    }

    public void refreshView() {
        if (this.recyclerView != null) {
            Objects.requireNonNull(this.recyclerView.getAdapter()).notifyDataSetChanged();
        }
    }

    private RecyclerView recyclerView;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_node_messages, container, false);
        // Set the adapter
        if (view instanceof RecyclerView) {
            Context context = view.getContext();
            recyclerView = (RecyclerView) view;
            if (mColumnCount <= 1) {
                recyclerView.setLayoutManager(new LinearLayoutManager(context));
            } else {
                recyclerView.setLayoutManager(new GridLayoutManager(context, mColumnCount));
            }

            recyclerView.setAdapter(new MyContactRecyclerViewAdapter(null));
        }
        return view;
    }
}