package com.lusna.user;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class HyperLANConnection {
    public HashMap<Long, PeerConnection> activeConnections;
    private String username;
    private long implicatedCid;
    // stored to allow reconnection in the case disconnection occurs
    private byte[] connectCommand;

    public HyperLANConnection(String username, byte[] connectCommand, long implicatedCid) {
        this.activeConnections = new HashMap<>();
        this.username = username;
        this.implicatedCid = implicatedCid;
        this.connectCommand = connectCommand;
    }

    public String getUsername() {
        return this.username;
    }

    public long getImplicatedCid() {
        return this.implicatedCid;
    }

    /// Command is ready to be sent to FFI.
    public byte[] getConnectCommand() {
        return this.connectCommand;
    }

    public List<String> getPeerUsernamesByCIDs(List<Long> cids) {
        return cids.stream().map(cid -> Optional.ofNullable(this.activeConnections.get(cid)))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .map(PeerConnection::getUsername)
                .collect(Collectors.toList());
    }
}
