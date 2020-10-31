package com.lusna.callbacks;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.example.lusna.PrimaryScreen;
import com.lusna.ffi.KernelConnection;
import com.lusna.ffi.deser.domain.DisconnectResponse;
import com.lusna.ffi.outbound.ToFFI;
import com.lusna.user.Users;
import com.lusna.util.ExponentialBackoffTracker;

public class Disconnect {
    public static boolean handleDisconnectResponse(@Nullable PrimaryScreen screen, @NonNull KernelConnection kConn, @NonNull DisconnectResponse dsr, boolean unexpected) {
        if (!unexpected) {
            switch (dsr.virtualConnectionType) {
                case HyperLANPeerToHyperLANServer:
                    return Users.tryRemoveConnection(dsr.implicated_cid);

                case HyperLANPeerToHyperLANPeer:
                    return Users.tryGet(dsr.implicated_cid)
                            .map(hyperLANConnection -> hyperLANConnection.activeConnections.remove(dsr.getTargetCID().orElse(-1L)) != null)
                    .orElse(false);

                default:
                    System.out.println("HyperWAN connections not yet implemented");
                    break;
            }
        } else {
            System.out.println("Will attempt to auto-reconnect");
            return Users.tryGet(dsr.implicated_cid)
                    .map(hyperLANConnection -> {
                        // The exponential backoff executor will keep executing until it is either finished, or if a success occurs
                        // As such, the lambda can always return false. Once the maximum number of executions is reached, it will stop
                        // 409600 = 100 * 2^x (x=12 iterations).
                        ExponentialBackoffTracker executor = new ExponentialBackoffTracker(100, 409600, () -> false);
                        ToFFI.sendConnectToFFI(null, kConn, hyperLANConnection.getUsername(), hyperLANConnection.getConnectCommand(), executor);
                        return true;
                    }).orElse(false);
        }

        return false;
    }
}
