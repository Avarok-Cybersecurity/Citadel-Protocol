package com.satori.verisend;

import android.app.ActivityManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;

import androidx.annotation.NonNull;

import com.google.firebase.messaging.FirebaseMessaging;
import com.satori.svc.Restarter;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import io.flutter.Log;
import io.flutter.embedding.android.FlutterActivity;
import io.flutter.embedding.engine.FlutterEngine;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.PluginRegistry;
import io.flutter.plugins.GeneratedPluginRegistrant;
//import io.flutter.plugins.firebasemessaging.FirebaseMessagingPlugin;
//import io.flutter.plugins.firebasemessaging.FlutterFirebaseMessagingService;

public class MainActivity extends FlutterActivity implements PluginRegistry.PluginRegistrantCallback {

    private static final String FFI_CHANNEL = "com.satori.verisend/native";
    public static MethodChannel dartConn = null;
    public static MainActivity activity;


    Intent mServiceIntent;
    //private VerisendService service;

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

    private void maybeStartService() {
        /*
        service = new VerisendService();
        mServiceIntent = new Intent(this, service.getClass());
        mServiceIntent.putExtra("inputExtra", "Messaging service is running in eco-mode");
        if (!isMyServiceRunning(service.getClass())) {
            startService(mServiceIntent);
        }*/
    }

    public void stopService() {
        //Intent serviceIntent = new Intent(this, LusnaService.class);
        // stopService(serviceIntent);
        //unbindService(svcConn);
    }

    @Override
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        activity = this;
        maybeStartService();
        //FlutterFirebaseMessagingService.setPluginRegistrant(this);
    }

    private void fcmInit() {
        FirebaseMessaging.getInstance().getToken()
                .addOnCompleteListener(task -> {
                    if (!task.isSuccessful()) {
                        Log.wtf("ERR", "Fetching FCM registration token failed", task.getException());
                        return;
                    }

                    // Get new FCM registration token
                    String token = task.getResult();

                    Log.wtf("FCM", "Client ID: " + token);
                    if (dartConn != null) {
                        dartConn.invokeMethod("fcmToken", token);
                    } else {
                        Log.wtf("FCM_ERR", "dartConn is null, thus cannot send token");
                    }
                });
    }

    private boolean isMyServiceRunning(Class<?> serviceClass) {
        ActivityManager manager = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
        for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
            if (serviceClass.getName().equals(service.service.getClassName())) {
                Log.i ("Service status", "Running");
                return true;
            }
        }
        Log.i ("Service status", "Not running");
        return false;
    }

    @Override
    protected void onDestroy() {
        //stopService(mServiceIntent);
        Intent broadcastIntent = new Intent();
        broadcastIntent.setAction("restartservice");
        broadcastIntent.setClass(this, Restarter.class);
        this.sendBroadcast(broadcastIntent);
        super.onDestroy();
    }

    @Override
    public void configureFlutterEngine(@NonNull FlutterEngine flutterEngine) {
        Log.wtf("DEBUG", "Initiating Java/Rust service ...");
        GeneratedPluginRegistrant.registerWith(flutterEngine);


        if (dartConn != null) {
            return;
        }
        
        dartConn = new MethodChannel(flutterEngine.getDartExecutor().getBinaryMessenger(), FFI_CHANNEL);

        dartConn.setMethodCallHandler((call, result) -> {
            Log.wtf("DEBUG", "Received Dart->Java FFI Command");
                    if (call.method.equals("sendToBackground")) {
                        moveTaskToBack(true);
                        result.success(null);
                    } else {
                        result.notImplemented();
                    }

                });

        //fcmInit();
    }

    @Override
    public void registerWith(PluginRegistry registry) {
        //FirebaseMessagingPlugin.registerWith(registry.registrarFor("io.flutter.plugins.firebasemessaging.FirebaseMessagingPlugin"));
        me.carda.awesome_notifications.AwesomeNotificationsPlugin.registerWith(registry.registrarFor("me.carda.awesome_notifications.AwesomeNotificationsPlugin"));
    }
}