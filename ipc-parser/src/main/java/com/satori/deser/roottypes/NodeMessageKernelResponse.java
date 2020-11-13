package com.satori.deser.roottypes;

import com.satori.deser.*;

import java.util.Optional;
import java.util.function.Consumer;

public class NodeMessageKernelResponse implements KernelResponse {
    private Consumer<KernelResponse> action = null;
    private final Ticket ticket;
    public long cid;
    public long icid;
    public long peer_cid;
    private final String message;

    public NodeMessageKernelResponse(Ticket ticket, long cid, long icid, long peer_cid, String message) {
        this.ticket = ticket;
        this.cid = cid;
        this.icid = icid;
        this.peer_cid = peer_cid;
        this.message = message;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return Optional.ofNullable(ticket);
    }

    @Override
    public KernelResponseType getType() {
        return KernelResponseType.NodeMessage;
    }

    @Override
    public Optional<String> getMessage() {
        return Optional.of(this.message);
    }

    @Override
    public Optional<DomainSpecificResponse> getDSR() {
        return Optional.empty();
    }

    @Override
    public Optional<Consumer<KernelResponse>> getCallbackAction() {
        return Optional.ofNullable(this.action);
    }

    @Override
    public void setCallbackAction(Consumer<KernelResponse> fx) {
        this.action = action;
    }

    public VirtualConnectionType getVirtualConnectionType() {
        if (this.icid != 0) {
            if (this.peer_cid != 0) {
                // nonzero icid && nonzero peer cid => HyperLAN Peer -> HyperWAN Peer
                return VirtualConnectionType.HyperLANPeerToHyperWANPeer;
            } else {
                // nonzero icid && zero peer cid => client -> hyperWAN server
                return VirtualConnectionType.HyperLANPeerToHyperWANServer;
            }
        } else {
            if (this.peer_cid != 0) {
                // zero icid && nonzero peer-cid => hyperlan p2p
                return VirtualConnectionType.HyperLANPeerToHyperLANPeer;
            } else {
                // zero icid && zero peer-cid => server to client message
                return VirtualConnectionType.HyperLANPeerToHyperLANServer;
            }
        }
    }
}
