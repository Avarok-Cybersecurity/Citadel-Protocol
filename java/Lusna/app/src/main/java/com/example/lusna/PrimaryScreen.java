package com.example.lusna;

import android.app.AlertDialog;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.util.AttributeSet;
import android.view.View;
import android.view.Menu;
import android.widget.TextView;

import com.example.lusna.ui.GlobalFragmentBundle;
import com.example.lusna.ui.home.HomeFragment;
import com.google.android.material.navigation.NavigationView;
import com.judemanutd.autostarter.AutoStartPermissionHelper;
import com.lusna.ffi.KernelConnection;
import com.lusna.ffi.TicketTracker;
import com.lusna.svc.LusnaService;
import com.lusna.util.NameViewModel;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.NavController;
import androidx.navigation.NavDestination;
import androidx.navigation.Navigation;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

public class PrimaryScreen extends AppCompatActivity {

    private AppBarConfiguration mAppBarConfiguration;
    //public String signature;
    public static GlobalFragmentBundle bundle = new GlobalFragmentBundle();
    private static boolean startedRustSubsystem = false;

    private HomeFragment homeFragment;

    public static NameViewModel rustModel;

    public static PrimaryScreen global;
    public static LusnaService service;

    static {
        System.loadLibrary("lusna_ffi");
    }

    private ServiceConnection svcConn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName componentName, IBinder iBinder) {
            System.out.println("Service bound!");
        }

        @Override
        public void onServiceDisconnected(ComponentName componentName) {
            System.out.println("Service unbound");
        }
    };

    public void startService() {
        Intent serviceIntent = new Intent(this, LusnaService.class);
        serviceIntent.putExtra("inputExtra", "Messaging service is running in eco-mode");
        //ContextCompat.startForegroundService(this, serviceIntent);
        bindService(serviceIntent, svcConn, Context.BIND_AUTO_CREATE);
    }

    public void stopService() {
        //Intent serviceIntent = new Intent(this, LusnaService.class);
        // stopService(serviceIntent);
        //unbindService(svcConn);
    }

    @Override
    protected void onStart() {
        super.onStart();
        System.out.println("Called onStart on primary activity");
        if (!startedRustSubsystem) {
            String fileDir = getFilesDir().toString();
            System.out.println("Will use directory " + fileDir);
            startService();
            startedRustSubsystem = true;
        } else {
            rustModel.refresh();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        System.out.println("onDestroy called");
        stopService();
    }

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        //getSupportFragmentManager().putFragment(outState, HomeFragment.TAG, homeFragment);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        System.out.println("onCreate being called (activity)");
        global = this;
        setContentView(R.layout.activity_primary_screen);
        if (savedInstanceState != null) {
            //Restore the fragment's instance
            homeFragment = (HomeFragment) getSupportFragmentManager().getFragment(savedInstanceState, HomeFragment.TAG);
        }

        Toolbar toolbar = findViewById(R.id.toolbar);

        setSupportActionBar(toolbar);
        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        NavigationView navigationView = findViewById(R.id.nav_view);
        // Passing each menu ID as a set of Ids because each
        // menu should be considered as top level destinations.
        mAppBarConfiguration = new AppBarConfiguration.Builder(
                R.id.nav_home, R.id.sessions_fragment, R.id.register_fragment, R.id.developerConsole)
                .setDrawerLayout(drawer)
                .build();
        PrimaryScreen thisRef = this;
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment);
        navController.addOnDestinationChangedListener(new NavController.OnDestinationChangedListener() {
            @Override
            public void onDestinationChanged(@NonNull NavController controller, @NonNull NavDestination destination, @Nullable Bundle arguments) {
                int menuId = destination.getId();
                switch (menuId) {
                    case R.id.nav_home:
                        break;
                    case R.id.register_fragment:
                        break;
                }
            }
        });
        NavigationUI.setupActionBarWithNavController(this, navController, mAppBarConfiguration);
        NavigationUI.setupWithNavController(navigationView, navController);

        // Other code to setup the activity...

        // Get the ViewModel.
        rustModel = new ViewModelProvider(this).get(NameViewModel.class);

        // Create the observer which updates the UI.
        final Observer<String> nameObserver = newName -> {
            // Update the UI, in this case, a TextView.
            System.out.println("Observer: onChanged called. Will set: " + newName);
            TextView textView = findViewById(R.id.rust_tag);
            if (textView != null) {
                textView.setText(newName);
            }
        };

        // Observe the LiveData, passing in this activity as the LifecycleOwner and the observer.
        rustModel.getCurrentName().observe(this, nameObserver);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.primary_screen, menu);
        return true;
    }

    @Override
    public boolean onSupportNavigateUp() {
        NavController navController = Navigation.findNavController(this, R.id.nav_host_fragment);
        return NavigationUI.navigateUp(navController, mAppBarConfiguration)
                || super.onSupportNavigateUp();
    }

    public <T extends View> T getComponent(int id) {
        return findViewById(id);
    }

    public void doConnect(View view) {
        com.lusna.guihandlers.EventHandlers.on_connect_button_pressed(this, service);
    }

    public void doRegister(View view) {
        com.lusna.guihandlers.EventHandlers.on_register_button_pressed(this, service);
    }
}