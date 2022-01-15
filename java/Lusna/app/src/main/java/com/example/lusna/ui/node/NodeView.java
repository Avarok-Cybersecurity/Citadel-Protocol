package com.example.lusna.ui.node;

import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProviders;
import androidx.viewpager2.widget.ViewPager2;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.example.lusna.R;
import com.example.lusna.ui.main.PageViewModel;
import com.example.lusna.ui.node.adapter.MyContactRecyclerViewAdapter;
import com.example.lusna.ui.node.adapter.NodePagerAdapter;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;
import com.lusna.ffi.deser.KernelResponseType;
import com.lusna.ffi.deser.domain.PeerList;
import com.lusna.ffi.outbound.FFIPacket;
import com.lusna.ffi.outbound.ToFFI;
import com.lusna.svc.LusnaService;
import com.lusna.user.Users;

import static com.lusna.ffi.outbound.FFIPacket.STD_COMMAND;

/**
 * A simple {@link Fragment} subclass.
 * Use the {@link NodeView#} method to
 * create an instance of this fragment.
 */
public class NodeView extends Fragment {

    private PageViewModel pageViewModel;
    private static final String ARG_SECTION_NUMBER = "section_number_node_home";
    protected String username;

    public NodeView(String username) {
        this.username = username;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        pageViewModel = ViewModelProviders.of(this).get(PageViewModel.class);
        int index = 1;
        if (getArguments() != null) {
            index = getArguments().getInt(ARG_SECTION_NUMBER);
        }
        pageViewModel.setIndex(index);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        System.out.println("SessionsFragment destroyed");
    }

    private ViewPager2 viewPager;
    private NodePagerAdapter adapter;
    private final String[] tabTitles = new String[] {"Home", "Actions", "Messages"};

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        TabLayout tabLayout = view.findViewById(R.id.tabLayout2);
        adapter = new NodePagerAdapter(this, Users.getSessionUsernames());

        viewPager = view.findViewById(R.id.view_pager_node);
        viewPager.setAdapter(adapter);


        LusnaService.getGlobalInstance()
                .ifPresent(kernel -> {
                    ToFFI.register_ffi_output(kernel.send_data(FFIPacket.prepareFFIPacket("switch " + username + " --cmd peer list", STD_COMMAND)), KernelResponseType.ResponseTicket, (kResp) -> {
                        kResp.getDSR()
                                .ifPresent(dsr_ -> {
                                    if (dsr_ instanceof PeerList) {
                                        PeerList dsr = (PeerList) dsr_;
                                        // here, we add 3 fragments: one for home, one for actions, one for messages
                                        adapter.addFragment(new NodeHomeFragment(username));
                                        adapter.addFragment(new NodeActionFragment(username));
                                        adapter.addFragment(new NodeMessagesFragment());

                                        new TabLayoutMediator(tabLayout, viewPager,
                                                (tab, position) -> tab.setText(tabTitles[position])
                                        ).attach();
                                        adapter.notifyDataSetChanged();
                                        /*
                                        clientsTable.addView(title);
                                        for (int i = 0; i < dsr.cids.size(); i++) {
                                            TableRow row = new TableRow(this.getContext());
                                            row.setLayoutParams(layoutParams);
                                            row.setVisibility(View.VISIBLE);
                                            TextView cid = new TextView(this.getContext());
                                            cid.setText("" + dsr.cids.get(i));
                                            cid.setLayoutParams(layoutParams);
                                            cid.setGravity(Gravity.CENTER);
                                            TextView is_online = new TextView(this.getContext());
                                            is_online.setText(dsr.is_onlines.get(i) ? "Online" : "Offline");
                                            is_online.setLayoutParams(layoutParams);
                                            is_online.setGravity(Gravity.CENTER);
                                            row.addView(cid);
                                            row.addView(is_online);
                                            clientsTable.addView(row, new TableLayout.LayoutParams(
                                                    TableLayout.LayoutParams.MATCH_PARENT,
                                                    TableLayout.LayoutParams.WRAP_CONTENT));
                                        }
                                        */
                                        //scrollView.addView(clientsTable);
                                    } else {
                                        System.out.println("DSR not instanceof PeerList");
                                    }
                                });
                    });
                });
    }

    @Override
    public View onCreateView(
            @NonNull LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_node_view, container, false);
    }
}