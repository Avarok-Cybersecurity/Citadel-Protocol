package com.lusna.callbacks;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.lusna.PrimaryScreen;
import com.lusna.user.Users;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.domain.ConnectResponse;
import com.lusna.util.AlertGenerator;

public class Connect {

    public static boolean onConnectResponseReceived(@Nullable PrimaryScreen screen, @NonNull KernelResponse kernelResponse, String username, byte[] connectCommand) {
        System.out.println("Connect callback success!");
        return kernelResponse.getDSR().map(domainSpecificResponse -> {
            System.out.println("DSR present");
            ConnectResponse connectResponse = (ConnectResponse) domainSpecificResponse;
            if (connectResponse.success) {
                Users.load(connectResponse, username, connectCommand);
                AlertGenerator.popup(screen, "Connect success", "Connection to " + username + " was a success!");
                return true;
            } else {
                AlertGenerator.popup(screen, "Connect failure", connectResponse.getMessage().orElse("Unable to connect. Please try again later"));
                return false;
            }
        }).orElse(false);
    }

}
