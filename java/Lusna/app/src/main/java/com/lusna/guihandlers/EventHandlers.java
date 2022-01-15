package com.lusna.guihandlers;

import android.util.Log;
import android.widget.TextView;

import com.example.lusna.PrimaryScreen;
import com.example.lusna.R;
import com.lusna.ffi.KernelConnection;
import com.lusna.ffi.outbound.ToFFI;
import com.lusna.svc.LusnaService;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;

import static com.lusna.ffi.outbound.FFIPacket.STD_COMMAND;
import static com.lusna.ffi.outbound.FFIPacket.prepareFFIPacket;

public class EventHandlers {

    public static void on_connect_button_pressed(PrimaryScreen activity, KernelConnection kConn) {
        Log.d("RUST_DEBUG", "Connect button pressed!");

        TextView usernameField = activity.getComponent(R.id.username);
        TextView passwordField = activity.getComponent(R.id.password);
        String username = usernameField.getText().toString();
        String password = passwordField.getText().toString();
        String cmd = "connect " + username + " --ffi --password " + password;
        System.out.println("Will execute: {}");
        byte[] ffiPacket = prepareFFIPacket(cmd, STD_COMMAND);
        ToFFI.sendConnectToFFI(activity, kConn, username, ffiPacket, null);
    }

    public static void on_register_button_pressed(PrimaryScreen activity, KernelConnection kConn) {
        TextView ipField = activity.getComponent(R.id.nodeIPTextBox);
        TextView fullNameField = activity.getComponent(R.id.fullname_register);
        TextView usernameField = activity.getComponent(R.id.username_register);
        TextView passwordField = activity.getComponent(R.id.password_register);
        TextView passwordField0 = activity.getComponent(R.id.password_register0);

        String password = passwordField.getText().toString();
        String password0 = passwordField0.getText().toString();

        if (!password.equals(password0)) {
            passwordField.setText("");
            passwordField.setHint("Passwords do not match");

            passwordField0.setText("");
            //passwordField.setHighlightColor(Color.rgb(220, 0, 0));
        } else {
            try {

                String addr = ipField.getText().toString();
                // No need to store the value; we only need to check to see that it doesn't throw an exception
                InetAddress.getByName(ipField.getText().toString());

                String username = usernameField.getText().toString();
                String fullname = fullNameField.getText().toString();

                if (!check_ascii(fullname)) {
                    passwordField.setText("");
                    passwordField.setHint("ASCII only");
                    return;
                }

                if (!check_ascii(username)) {
                    usernameField.setText("");
                    usernameField.setHint("ASCII only");
                    return;
                }

                if (username.contains(" ")) {
                    usernameField.setText("");
                    usernameField.setHint("No spaces allowed");
                    return;
                }

                if (!check_ascii(password)) {
                    passwordField.setText("");
                    passwordField.setHint("ASCII only");
                    return;
                }

                String command = "register "  + addr + " --ffi --username " + username + " --password " + password + " --fullname " + fullname;
                System.out.println("Will execute: " + command);
                byte[] ffiPacket = prepareFFIPacket(command, STD_COMMAND);
                ToFFI.sendRegisterToFFI(activity, kConn, ffiPacket);
            } catch (UnknownHostException e) {
                ipField.setHint("Invalid IP Address");
            }
        }
    }

    private static boolean check_ascii(String input) {
        return input.matches("\\A\\p{ASCII}*\\z");
    }
}
