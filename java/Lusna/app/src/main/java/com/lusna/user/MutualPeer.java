package com.lusna.user;

/*
    A container for keeping track of a user's mutual contact in a HyperLAN/WAN
 */
public class MutualPeer {
    private String username;
    private long cid;
    // 0 for hyperlan peers
    private long icid;

    private MutualPeer(String username, long cid, long icid) {
        this.username = username;
        this.cid = cid;
        this.icid = icid;
    }

    public MutualPeer newHyperLAN(String username, long cid) {
        return new MutualPeer(username, cid, 0);
    }

    public MutualPeer newHyperWAN(String username, long cid, long icid) {
        return new MutualPeer(username, cid, icid);
    }

    public String getUsername() {
        return username;
    }

    public long getCID() {
        return cid;
    }

    public long getInterserverCID() {
        return icid;
    }
}
