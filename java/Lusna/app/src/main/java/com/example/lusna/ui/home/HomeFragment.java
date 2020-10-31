package com.example.lusna.ui.home;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelProviders;

import com.example.lusna.PrimaryScreen;
import com.example.lusna.R;
import com.lusna.util.NameViewModel;

import java.io.Serializable;

public class HomeFragment extends Fragment {

    private NameViewModel rustTagModel;
    public static String TAG = "HomeFragment";
    public static String SIGNATURE_TAG = "SIGNATURE";

    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        View root = inflater.inflate(R.layout.fragment_home, container, false);
        setRetainInstance(true);
        PrimaryScreen.bundle.tryGetValue(TAG, SIGNATURE_TAG)
                .ifPresent(val -> ((TextView) root.findViewById(R.id.rust_tag)).setText(val));
        System.out.println("HomeFragment onCreateView called");
        return root;
    }

    @Override
    public void onSaveInstanceState(@NonNull final Bundle outState) {
        super.onSaveInstanceState(outState);
        System.out.println("Calling onSaveInstanceState");
        outState.putSerializable("rustTagModel", rustTagModel.getValue());
    }

    @Override
    public void onActivityCreated(Bundle savedInstanceState) {
        super.onActivityCreated(savedInstanceState);
        System.out.println("onActivityCreated called");
        if (savedInstanceState != null) {
            //probably orientation change
            System.out.println("Bundle non-null");
            rustTagModel = NameViewModel.from(savedInstanceState.getString("rustTagModel"));
        } else {
            if (rustTagModel != null) {
                System.out.println("No action needed");
                //returning from backstack, data is fine, do nothing
            } else {
                //newly created, compute data
                System.out.println("Updating data");
                rustTagModel = PrimaryScreen.rustModel;
                rustTagModel.refresh();
            }
        }
    }

}