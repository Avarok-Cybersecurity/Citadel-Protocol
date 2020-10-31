package com.lusna.user;

import com.lusna.ffi.deser.domain.ConnectResponse;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class Users {

    /// The Long value <=> CID
    private static ConcurrentHashMap<Long, HyperLANConnection> ACTIVE_HLAN_CONNECTIONS = new ConcurrentHashMap<>();
    // cid, peer-cid -> mutual peer
    private static ConcurrentHashMap<Long, HashMap<Long, MutualPeer>> MUTUAL_PEERS = new ConcurrentHashMap<>();

    public static void load(ConnectResponse resp, String username, byte[] connectCommand) {
        ACTIVE_HLAN_CONNECTIONS.put(resp.getCID(), new HyperLANConnection(username, connectCommand, resp.getCID()));
    }

    public static Optional<HyperLANConnection> tryGet(long implicatedCid) {
        HyperLANConnection conn = ACTIVE_HLAN_CONNECTIONS.get(implicatedCid);
        return conn != null ? Optional.of(conn) : Optional.empty();
    }

    // this only removes the entry from the hashmap, but doesn't actually stop the connection
    public static boolean tryRemoveConnection(long implicatedCid) {
        return ACTIVE_HLAN_CONNECTIONS.remove(implicatedCid) != null;
    }

    public static List<String> getSessionUsernames() {
        return ACTIVE_HLAN_CONNECTIONS.values().stream().map(HyperLANConnection::getUsername).collect(Collectors.toList());
    }

    public static Optional<HyperLANConnection> tryGetConnectionByUsername(String username) {
        return ACTIVE_HLAN_CONNECTIONS.values().stream().filter(hyperLANConnection -> hyperLANConnection.getUsername().equals(username)).findFirst();
    }

    public static Optional<MutualPeer> tryGetMutualPeerByCID(long cid, long peer_cid) {
        return Optional.ofNullable(MUTUAL_PEERS.get(cid))
                .flatMap(map -> Optional.ofNullable(map.get(peer_cid)));
    }

    public static void insertMutualPeer(long cid, MutualPeer peer) {
        HashMap<Long, MutualPeer> map = MUTUAL_PEERS.get(cid);
        if (map != null) {
            map.put(peer.getCID(), peer);
        } else {
            HashMap<Long, MutualPeer> map_ = new HashMap<>();
            map_.put(peer.getCID(), peer);
            MUTUAL_PEERS.put(cid, map_);
        }
    }

    public static void insertMutualPeers(long cid, List<MutualPeer> peers) {
        HashMap<Long, MutualPeer> map = MUTUAL_PEERS.get(cid);
        if (map != null) {
            for (MutualPeer peer : peers){
                map.put(peer.getCID(), peer);
            }
        } else {
            HashMap<Long, MutualPeer> map_ = new HashMap<>();
            for (MutualPeer peer : peers){
                map_.put(peer.getCID(), peer);
            }
            MUTUAL_PEERS.put(cid, map_);
        }
    }
}
