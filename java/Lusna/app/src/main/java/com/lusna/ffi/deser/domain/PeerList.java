package com.lusna.ffi.deser.domain;

import androidx.annotation.NonNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.lusna.ffi.Ticket;
import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.DomainSpecificResponseType;
import com.lusna.util.Iterators;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class PeerList implements DomainSpecificResponse {
    public List<Long> cids;
    public List<Boolean> is_onlines;
    private Ticket ticket;

    @Override
    public DomainSpecificResponseType getType() {
        return DomainSpecificResponseType.PeerList;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return Optional.of(this.ticket);
    }

    @Override
    public Optional<String> getMessage() {
        return Optional.empty();
    }

    @Override
    public Optional<DomainSpecificResponse> deserializeFrom(JsonNode node) {
        //cids: Vec<u64>,
        //is_onlines: Vec<bool>,
        //ticket: u64
        JsonNode cids_node = node.findValue("cids");
        List<Long> cids = Iterators.iterToStream(cids_node.iterator()).map(JsonNode::longValue).collect(Collectors.toList());

        JsonNode isonline_node = node.findValue("is_onlines");
        List<Boolean> is_onlines = Iterators.iterToStream(isonline_node.iterator()).map(JsonNode::booleanValue).collect(Collectors.toList());

        Optional<Ticket> ticket_opt = Ticket.tryFrom(node.findValue("ticket").longValue());
        if (!ticket_opt.isPresent()) {
            return Optional.empty();
        } else {
            this.cids = cids;
            this.is_onlines = is_onlines;
            this.ticket = ticket_opt.get();
            return Optional.of(this);
        }
    }
}
