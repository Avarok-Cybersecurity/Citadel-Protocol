package com.lusna.user;

public class PeerConnection {
    private String username;
    private long cid;

    public PeerConnection(String username, long cid) {
        this.username = username;
        this.cid = cid;
    }

    public String getUsername() {
        return this.username;
    }

    public long getCid() {
        return this.cid;
    }
}
