package com.lusna.ffi.deser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lusna.ffi.Ticket;
import com.lusna.ffi.deser.domain.DSRParser;
import com.lusna.ffi.deser.roottypes.ConfirmationKernelResponse;
import com.lusna.ffi.deser.roottypes.ErrorKernelResponse;
import com.lusna.ffi.deser.roottypes.HybridKernelResponse;
import com.lusna.ffi.deser.roottypes.MessageKernelResponse;
import com.lusna.ffi.deser.roottypes.NodeMessageKernelResponse;
import com.lusna.ffi.deser.roottypes.TicketKernelResponse;

import java.util.Iterator;
import java.util.Optional;

//    Confirmation,
//    Response(String),
//    ResponseTicket(u64),
//    ResponseHybrid(u64, String),
//    DomainSpecificResponse(DomainResponse),
//    Error(u64, String),
public class KernelResponseDeserializer {
    public static Optional<KernelResponse> tryFrom(String json) {
        JsonNode outerNode;
        try {
            outerNode = new ObjectMapper().readTree(json);
        } catch (Exception e) {
            return Optional.empty();
        }
        assert outerNode != null;
        String typeString = outerNode.get("type").textValue();
        KernelResponseType type = KernelResponseType.valueOf(typeString);
        System.out.println("[Deser] Type: " + type);
        JsonNode infoNode = outerNode.get("info");
        switch (type) {
            case Confirmation:
                return Optional.of(new ConfirmationKernelResponse());

            case Message:
                // info has 1 field value. Take it
                return Optional.of(new MessageKernelResponse(infoNode.textValue()));

            case ResponseTicket:
                // just a u64 field
                return Optional.of(new TicketKernelResponse(new Ticket(infoNode.longValue())));

            case ResponseHybrid:
                return parseHybridResponse(infoNode.elements());

            case NodeMessage:
                return parseNodeMessageResponse(infoNode.elements());

            case Error:
                return parseErrorResponse(infoNode.elements());

            case DomainSpecificResponse:
                return DSRParser.tryFrom(infoNode);
        }

        return Optional.empty();
    }

    private static Optional<KernelResponse> parseHybridResponse(Iterator<JsonNode> values) {
        // a u64 and a string;
        if (!values.hasNext()) {
            return Optional.empty();
        }
        Ticket ticket = new Ticket(values.next().longValue());

        if (!values.hasNext()) {
            return Optional.empty();
        }
        String message = values.next().textValue();
        return Optional.of(new HybridKernelResponse(ticket, message));
    }

    private static Optional<KernelResponse> parseErrorResponse(Iterator<JsonNode> values) {
        if (!values.hasNext()) {
            return Optional.empty();
        }
        Optional<Ticket> ticket1 = Ticket.tryFrom(values.next().longValue());

        if (!values.hasNext()) {
            return Optional.empty();
        }
        String message1 = values.next().textValue();
        return Optional.of(new ErrorKernelResponse(ticket1, message1));
    }

    private static Optional<KernelResponse> parseNodeMessageResponse(Iterator<JsonNode> values) {
        if (!values.hasNext()) {
            return Optional.empty();
        }

        Ticket ticket = new Ticket(values.next().longValue());
        if (!values.hasNext()) {
            return Optional.empty();
        }
        long implicated_cid = values.next().longValue();

        if (!values.hasNext()) {
            return Optional.empty();
        }

        long icid = values.next().longValue();

        if (!values.hasNext()) {
            return Optional.empty();
        }

        long peer_cid = values.next().longValue();

        if (!values.hasNext()) {
            return Optional.empty();
        }

        String message = values.next().textValue();
        return Optional.of(new NodeMessageKernelResponse(ticket, implicated_cid, icid, peer_cid, message));
    }
}