package com.lusna.ffi.deser.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.DomainSpecificResponseType;
import com.lusna.ffi.Ticket;

import java.util.Iterator;
import java.util.Optional;

//    Success(u64, String),
//    Failure(u64, String)
public class RegisterResponse implements DomainSpecificResponse {
    public boolean success;
    private Ticket ticket;
    private String message;

    protected RegisterResponse() {}

    private RegisterResponse(String message, Ticket ticket, boolean success) {
        this.message = message;
        this.ticket = ticket;
        this.success = success;
    }

    @Override
    public DomainSpecificResponseType getType() {
        return DomainSpecificResponseType.Register;
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

    private static Optional<DomainSpecificResponse> deserialize_inner(JsonNode node, boolean success) {
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

        String message = values.next().textValue();
        return Optional.of(new RegisterResponse(message, ticket, success));
    }
}
