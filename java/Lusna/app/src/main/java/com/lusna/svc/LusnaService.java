package com.lusna.svc;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.work.Constraints;
import androidx.work.ListenableWorker;
import androidx.work.NetworkType;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import com.example.lusna.DeveloperConsole;
import com.example.lusna.PrimaryScreen;
import com.example.lusna.R;
import com.google.common.util.concurrent.ListenableFuture;
import com.lusna.ffi.KernelConnection;
import com.lusna.ffi.TicketTracker;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static androidx.work.PeriodicWorkRequest.MIN_PERIODIC_INTERVAL_MILLIS;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.os.IBinder;

public class LusnaService extends Service implements KernelConnection {
    public static final String CHANNEL_ID = "LusnaServiceChannel";
    private static LusnaService global;

    public static Optional<LusnaService> getGlobalInstance() {
        return Optional.ofNullable(global);
    }

    @Override
    public void onCreate() {
        System.out.println("onCreate LusnaService executed");
        global = this;
        super.onCreate();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        PrimaryScreen.service = this;
        System.out.println("onStartCommand for LusnaService executed ...");
        System.out.println("Starting rust subsystem!");
        String fileDir = getFilesDir().toString();
        System.out.println("Will use directory " + fileDir);
        String tag = this.start_rust_subsystem(fileDir.getBytes(StandardCharsets.UTF_8));
        System.out.println("Obtained tag: " + tag);
        // post below is false since this is called on the main thread already
        PrimaryScreen.rustModel.setText(tag, false);
        String input = intent.getStringExtra("inputExtra");
        createNotificationChannel();

        // this intent makes the foreground icon redirect user clicks to PrimaryScreen.class
        Intent notificationIntent = new Intent(this, PrimaryScreen.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this,
                0, notificationIntent, 0);
        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Lusna Encryption Module")
                .setContentText(input)
                .setColorized(true)
                .setColor(Color.rgb(139, 113, 181))
                .setSmallIcon(R.mipmap.lusna_notification_icon2_foreground)
                .setContentIntent(pendingIntent)
                .build();

        startForeground(1, notification);
        return START_NOT_STICKY;
    }
    @Override
    public void onDestroy() {
        super.onDestroy();
        System.out.println("Service onDestroy called");
    }


    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        System.out.println("onBind called");
        this.onStartCommand(intent, 0, 0);
        return null;
    }

    private NotificationManager manager;
    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel serviceChannel = new NotificationChannel(
                    CHANNEL_ID,
                    "Lusna Kernel",
                    NotificationManager.IMPORTANCE_DEFAULT
            );
            serviceChannel.enableLights(true);
            serviceChannel.setLightColor(Color.rgb(139, 113, 181));
            NotificationManager manager = getSystemService(NotificationManager.class);
            manager.createNotificationChannel(serviceChannel);
        }
    }

    public native byte[] send_data(byte[] bytes);
    public native String start_rust_subsystem(byte[] homeDir);

    public static ExecutorService executor = Executors.newSingleThreadExecutor();

    private int nid = 2;
    /*
        Important: We MUST offload the task to the executor above, otherwise, we block the rust kernel
        from continuing execution.
     */
    public void ffiCallback(byte[] input) {
        System.out.println("FFI Callback ran!");
        String json = new String(input, StandardCharsets.UTF_8);
        executor.submit(() -> {
            NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
                    .setSmallIcon(R.mipmap.lusna_notification_icon2_foreground)
                    .setContentTitle("Lusna")
                    .setColorized(true)
                    .setLights(Color.rgb(139, 113, 181), 500, 2000)
                    .setColor(Color.rgb(139, 113, 181))
                    .setContentText(json)
                    .setPriority(NotificationCompat.PRIORITY_DEFAULT);
            NotificationManagerCompat notificationManager = NotificationManagerCompat.from(this);

            Notification built = builder.build();
            notificationManager.notify(nid++, built);
        });


        if (DeveloperConsole.consoleLog != null) {
            DeveloperConsole.consoleLog.appendText(json, '\n', true);
        } else {
            PrimaryScreen.bundle.appendToEntry(DeveloperConsole.TAG, DeveloperConsole.TERMINAL_TEXT_TAG, json, '\n');
        }

        executor.submit(() -> TicketTracker.onResponseReceived(this, input));
    }
}