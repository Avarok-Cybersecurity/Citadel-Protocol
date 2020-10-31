package com.lusna.util;

import android.app.AlertDialog;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.lusna.PrimaryScreen;

public class AlertGenerator {
    /// This runs the closure on the UI thread as required
    public static void popup(@Nullable PrimaryScreen screen, String title, String message) {
        if (screen != null) {
            screen.runOnUiThread( () -> {
                AlertDialog alertDialog = new AlertDialog.Builder(screen).create();
                alertDialog.setTitle(title);
                alertDialog.setMessage(message);
                alertDialog.setButton(AlertDialog.BUTTON_NEUTRAL, "OK",
                        (dialog, which) -> dialog.dismiss());
                alertDialog.show();
            });
        } else {
            // for now, just print some debug info
            System.out.println("Screen is null. Will instead print message (title=" + title + "): " + message);
        }
    }
}
