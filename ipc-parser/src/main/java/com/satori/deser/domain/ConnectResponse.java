package com.satori.deser.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.satori.deser.DomainSpecificResponse;
import com.satori.deser.DomainSpecificResponseType;
import com.satori.deser.Ticket;

import java.util.Iterator;
import java.util.Optional;

//    Success(u64, u64, String),
//    Failure(u64, u64, String)
public class ConnectResponse implements DomainSpecificResponse {
    public boolean success;
    private Ticket ticket;
    public long implicated_cid;
    private String message;

    protected ConnectResponse() {}

    @Override
    public DomainSpecificResponseType getType() {
        return DomainSpecificResponseType.Connect;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return Optional.of(this.ticket);
    }

    @Override
    public Optional<String> getMessage() {
        return Optional.of(this.message);
    }

    @Override
    public Optional<DomainSpecificResponse> deserializeFrom(JsonNode infoNode) {
        // debug purposes. Iterator<JsonNode> values1 = infoNode.elements();
        JsonNode successNode = infoNode.get("Success");
        if (successNode != null) {
            return deserialize_inner(successNode, true);
        }

        JsonNode failureNode = infoNode.get("Failure");
        if (failureNode != null) {
            return deserialize_inner(failureNode, false);
        }


        return Optional.empty();
    }

    private Optional<DomainSpecificResponse> deserialize_inner(JsonNode node, boolean success) {
        Iterator<JsonNode> values = node.elements();
        if (!values.hasNext()) {
            return Optional.empty();
        }

        Optional<Ticket> ticket_opt = Ticket.tryFrom(values.next().longValue());
        if (!ticket_opt.isPresent()) {
            return Optional.empty();
        }

        Ticket ticket = ticket_opt.get();

        if (!values.hasNext()) {
            return Optional.empty();
        }

        long implicated_cid = values.next().longValue();

        if (!values.hasNext()) {
            return Optional.empty();
        }

        this.success = success;
        this.ticket = ticket;
        this.message = values.next().textValue();
        this.implicated_cid = implicated_cid;
        return Optional.of(this);
    }

    public long getCID() {
        return this.implicated_cid;
    }
}
