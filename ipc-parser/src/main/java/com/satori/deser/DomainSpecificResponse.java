package com.satori.deser;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Optional;

//    GetActiveSessions(ActiveSessions),
//    GetAccounts(ActiveAccounts),
//    Register(RegisterResponse),
//    Connect(ConnectResponse)
public interface DomainSpecificResponse {
    DomainSpecificResponseType getType();
    Optional<Ticket> getTicket();
    Optional<String> getMessage();
    Optional<DomainSpecificResponse> deserializeFrom(JsonNode node);
}