package com.lusna.ffi;

import androidx.annotation.NonNull;

import com.example.lusna.PrimaryScreen;
import com.lusna.callbacks.Disconnect;
import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.domain.ConnectResponse;
import com.lusna.ffi.deser.domain.DisconnectResponse;
import com.lusna.ffi.deser.domain.GetAccounts;
import com.lusna.ffi.deser.domain.GetActiveSessions;
import com.lusna.ffi.deser.domain.RegisterResponse;

import java.util.Optional;

public class UntrackedKernelResponseHandler {
    public static void handleUntrackedMessage(KernelResponse kernelResponse, @NonNull KernelConnection kConn) {
        Optional<DomainSpecificResponse> kDSR = kernelResponse.getDSR();
        if (kDSR.isPresent()) {
            handleDSRResponse(kDSR.get(), kConn);
        } else {
            handleNonDSRResponse(kernelResponse);
        }
    }

    private static void handleDSRResponse(DomainSpecificResponse dsr, @NonNull KernelConnection kConn) {
        if (dsr instanceof DisconnectResponse) {
            if (Disconnect.handleDisconnectResponse(PrimaryScreen.global, kConn, (DisconnectResponse) dsr, true)) {
                System.out.println("Successfully processed DSR signal");
            } else {
                System.out.println("Failure processing DSR signal");
            }
        } else if (dsr instanceof ConnectResponse) {

        } else if (dsr instanceof GetAccounts) {

        } else if (dsr instanceof GetActiveSessions) {

        } else if (dsr instanceof RegisterResponse) {

        }
    }

    private static void handleNonDSRResponse(KernelResponse kernelResponse) {

    }
}
