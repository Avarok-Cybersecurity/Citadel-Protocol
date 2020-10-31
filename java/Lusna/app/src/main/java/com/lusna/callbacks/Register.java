package com.lusna.callbacks;

import androidx.annotation.NonNull;

import com.example.lusna.PrimaryScreen;
import com.example.lusna.RegisterFragment;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.domain.RegisterResponse;
import com.lusna.util.AlertGenerator;

public class Register {

    public static void onRegisterResponseReceived(@NonNull PrimaryScreen screen, @NonNull KernelResponse response) {
        System.out.println("Callback for register type success!");
        response.getDSR().ifPresent(dsr -> {
            System.out.println("DSR present");
            RegisterResponse dsrResp = (RegisterResponse) dsr;
            if (dsrResp.success) {
                AlertGenerator.popup(screen, "Success", "You may now login");
            } else {
                AlertGenerator.popup(screen, "Unable to register", dsrResp.getMessage().orElse("Make sure the connection is valid"));
            }
        });
    }

}
