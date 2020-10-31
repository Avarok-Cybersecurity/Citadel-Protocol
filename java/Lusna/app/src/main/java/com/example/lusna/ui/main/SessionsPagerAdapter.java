package com.example.lusna.ui.main;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import com.example.lusna.ui.node.NodeView;
import com.lusna.user.Users;

import java.util.ArrayList;
import java.util.List;

/**
 * A [FragmentPagerAdapter] that returns a fragment corresponding to
 * one of the sections/tabs/pages.
 */
public class SessionsPagerAdapter extends FragmentStateAdapter {

    private final List<Fragment> fragments = new ArrayList<>();
    private List<String> usernames;

    public SessionsPagerAdapter(Fragment fragment, List<String> usernames) {
        super(fragment);
        this.usernames = usernames;
    }

    public void addFragment(Fragment fragment) {
        this.fragments.add(fragment);
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        Fragment frag = this.fragments.get(position);
        return frag != null ? frag : new NodeView(this.usernames.get(position));
    }

    @Override
    public int getItemCount() {
        return fragments.size();
    }
}