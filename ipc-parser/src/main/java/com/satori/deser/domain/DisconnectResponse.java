package com.satori.deser.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.satori.deser.DomainSpecificResponse;
import com.satori.deser.DomainSpecificResponseType;
import com.satori.deser.Ticket;
import com.satori.deser.VirtualConnectionType;

import java.util.Iterator;
import java.util.Optional;

public class DisconnectResponse implements DomainSpecificResponse {
    public VirtualConnectionType virtualConnectionType;
    public long implicated_cid;
    private Long target_cid;
    private Ticket ticket;

    @Override
    public DomainSpecificResponseType getType() {
        return null;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return this.ticket != null ? Optional.of(this.ticket) : Optional.empty();
    }

    @Override
    public Optional<String> getMessage() {
        return Optional.empty();
    }

    @Override
    public Optional<DomainSpecificResponse> deserializeFrom(JsonNode infoNode) {
        // debug purposes. Iterator<JsonNode> values1 = infoNode.elements();
        JsonNode hLANp2s = infoNode.get("HyperLANPeerToHyperLANServer");
        if (hLANp2s != null) {
            // first value is the ticket, the second, the implicated CID
            Iterator<JsonNode> values = hLANp2s.elements();
            if (!values.hasNext()) {
                return Optional.empty();
            }

            Optional<Ticket> ticket_opt = Ticket.tryFrom(values.next().longValue());

            if (!values.hasNext()) {
                return Optional.empty();
            }

            this.implicated_cid = values.next().longValue();
            this.ticket = ticket_opt.orElse(null);
            this.virtualConnectionType = VirtualConnectionType.HyperLANPeerToHyperLANServer;
            return Optional.of(this);
        }

        JsonNode hLANp2p = infoNode.get("HyperLANPeerToHyperLANPeer");
        if (hLANp2p != null) {
            // first value is the ticket, the second, the implicated CID
            Iterator<JsonNode> values = hLANp2p.elements();
            if (!values.hasNext()) {
                return Optional.empty();
            }

            Optional<Ticket> ticket_opt = Ticket.tryFrom(values.next().longValue());

            if (!values.hasNext()) {
                return Optional.empty();
            }

            long implicated_cid = values.next().longValue();

            if (!values.hasNext()) {
                return Optional.empty();
            }

            this.implicated_cid = implicated_cid;
            this.target_cid = values.next().longValue();
            this.ticket = ticket_opt.orElse(null);
            this.virtualConnectionType = VirtualConnectionType.HyperLANPeerToHyperLANPeer;
            return Optional.of(this);
        }


        return Optional.empty();
    }

    // This value won't exist if the connection type is a p2s type
    public Optional<Long> getTargetCID() {
        return Optional.ofNullable(this.target_cid);
    }
}
