package com.example.lusna.ui.main;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProviders;
import androidx.viewpager2.widget.ViewPager2;

import com.example.lusna.ui.node.NodeView;
import com.example.lusna.R;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;
import com.lusna.user.Users;

import java.util.List;

/**
 * A placeholder fragment containing a simple view.
 */
public class SessionsFragment extends Fragment {

    private static final String ARG_SECTION_NUMBER = "section_number_sessions";
    private static final String TAG = "SessionsFragment";
    private static final String TAB_TAG_BASE = "TAB_BASE";

    private PageViewModel pageViewModel;
    private int index;

    public static SessionsFragment newInstance(int index) {
        SessionsFragment fragment = new SessionsFragment();
        Bundle bundle = new Bundle();
        bundle.putInt(ARG_SECTION_NUMBER, index);
        fragment.setArguments(bundle);
        fragment.index = index;
        return fragment;
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
    private SessionsPagerAdapter adapter;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        TabLayout tabLayout = view.findViewById(R.id.tabLayout);

        List<String> usernames = Users.getSessionUsernames();
        adapter = new SessionsPagerAdapter(this, usernames);

        System.out.println("[SessionsFragment] Active sessions detected: " + usernames.size());
        usernames.forEach(username -> adapter.addFragment(new NodeView(username)));

        viewPager = view.findViewById(R.id.view_pager);
        viewPager.setAdapter(adapter);
        new TabLayoutMediator(tabLayout, viewPager,
                (tab, position) -> tab.setText(usernames.get(position))
        ).attach();
    }

    @Override
    public View onCreateView(
            @NonNull LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_sessions, container, false);
    }
}