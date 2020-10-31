package com.example.lusna;

import android.os.Bundle;

import androidx.fragment.app.Fragment;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelProvider;

import android.text.method.ScrollingMovementMethod;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.lusna.util.NameViewModel;

/**
 * A simple {@link Fragment} subclass.
 * Use the {@link DeveloperConsole#newInstance} factory method to
 * create an instance of this fragment.
 */
public class DeveloperConsole extends Fragment {

    // TODO: Rename parameter arguments, choose names that match
    // the fragment initialization parameters, e.g. ARG_ITEM_NUMBER
    private static final String ARG_PARAM1 = "param1";
    private static final String ARG_PARAM2 = "param2";
    public static String TAG = "DEV_CONSOLE";
    public static String TERMINAL_TEXT_TAG = "TERM_TEXT";

    // TODO: Rename and change types of parameters
    private String mParam1;
    private String mParam2;

    public DeveloperConsole() {
        // Required empty public constructor
    }

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @param param1 Parameter 1.
     * @param param2 Parameter 2.
     * @return A new instance of fragment DeveloperConsole.
     */
    // TODO: Rename and change types and number of parameters
    public static DeveloperConsole newInstance(String param1, String param2) {
        DeveloperConsole fragment = new DeveloperConsole();
        Bundle args = new Bundle();
        args.putString(ARG_PARAM1, param1);
        args.putString(ARG_PARAM2, param2);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            mParam1 = getArguments().getString(ARG_PARAM1);
            mParam2 = getArguments().getString(ARG_PARAM2);
        }
    }

    private View view;
    public static NameViewModel consoleLog;
    private Observer<String> observer;
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        // Inflate the layout for this fragment
        view = inflater.inflate(R.layout.fragment_developer_console, container, false);
        TextView textView = view.findViewById(R.id.consoleLogText);
        textView.setMovementMethod(new ScrollingMovementMethod());

        observer = new Observer<String>() {
            @Override
            public void onChanged(String s) {
                System.out.println("About to update Console data to: " + s);
                textView.setText(s);
            }
        };

        if (consoleLog == null) {
            consoleLog = new ViewModelProvider(this).get(NameViewModel.class);
            PrimaryScreen.bundle.tryGetValue(TAG, TERMINAL_TEXT_TAG)
                    .ifPresent(data -> consoleLog.setText(data, false));
        }

        consoleLog.getCurrentName().observe(getViewLifecycleOwner(), observer);
        return view;
    }
}