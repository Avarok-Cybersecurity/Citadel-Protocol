package com.lusna.ffi.outbound;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.lusna.PrimaryScreen;
import com.lusna.callbacks.Connect;
import com.lusna.callbacks.Register;
import com.lusna.ffi.KernelConnection;
import com.lusna.ffi.TicketTracker;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.KernelResponseDeserializer;
import com.lusna.ffi.deser.KernelResponseType;
import com.lusna.util.AlertGenerator;
import com.lusna.util.ExponentialBackoffTracker;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Consumer;

public class ToFFI {

    // If executor is non-null, then the executor will be driven to completion
    public static void sendConnectToFFI(@Nullable PrimaryScreen activity, @NonNull KernelConnection kConn, String username, byte[] ffiPacket, @Nullable ExponentialBackoffTracker executor) {
        register_ffi_output(kConn.send_data(ffiPacket), KernelResponseType.ResponseTicket, (kernelResponse -> {
            if (!Connect.onConnectResponseReceived(activity, kernelResponse, username, ffiPacket)) {
                if (executor != null) {
                    if (!executor.isFinished()) {
                        new Timer().schedule(new TimerTask() {
                            @Override
                            public void run() {
                                executor.revolution();
                                sendConnectToFFI(activity, kConn, username, ffiPacket, executor);
                            }
                        }, executor.getCurrentValue());
                    } else {
                        System.out.println("Exponential backoff executor has finished; will not execute again");
                    }
                }
            }
        })).ifPresent((err) -> {
            if (activity != null) {
                AlertGenerator.popup(activity, "Input error", err);
            }
        });
    }

    public static void sendRegisterToFFI(@NonNull PrimaryScreen activity, @NonNull KernelConnection kConn, byte[] ffiPacket) {
        register_ffi_output(kConn.send_data(ffiPacket), KernelResponseType.ResponseTicket, kMsg -> {
            Register.onRegisterResponseReceived(activity, kMsg);
        }).ifPresent(err -> {
            AlertGenerator.popup(activity, "Input error", err);
        });
    }

    /*
        Optionally returns an error message
    */
    public static Optional<String> register_ffi_output(byte[] output, KernelResponseType type, Consumer<KernelResponse> onResponseReceived) {
        String response = new String(output, StandardCharsets.UTF_8);
        System.out.println("Resp: " + response);
        Optional<KernelResponse> kernelResponse = KernelResponseDeserializer.tryFrom(response);
        if (kernelResponse.isPresent()) {
            KernelResponse kResp = kernelResponse.get();
            if (kResp.getType() != type) {
                System.out.println("Invalid type. Expected: " + type + ", received: " + kResp.getType());
                return Optional.of(kResp.getMessage().orElse("Unexpected kernel response. Please double check your input, and try again."));
            }

            if (!kResp.getTicket().isPresent()) {
                System.err.println("No ticket present in the response. Cannot register");
                return Optional.empty();
            }

            if (onResponseReceived != null) {
                kResp.setCallbackAction(onResponseReceived);
            }

            kResp.getTicket().ifPresent(ticket -> {
                System.out.println("Adding ticket " + ticket.getValue() + " to the registry");
                TicketTracker.insert(ticket, kResp);
            });
        } else {
            System.out.println("kernel response is Empty. Bad packet?");
        }

        return Optional.empty();
    }
}
