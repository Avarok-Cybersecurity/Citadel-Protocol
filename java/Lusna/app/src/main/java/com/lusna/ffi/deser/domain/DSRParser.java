package com.lusna.ffi.deser.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.DomainSpecificResponseType;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.domain.ConnectResponse;
import com.lusna.ffi.deser.roottypes.DomainSpecificKernelResponse;

import java.util.Optional;

public class DSRParser {

    public static Optional<KernelResponse> tryFrom(JsonNode infoNode) {
        JsonNode dsrNodeTmp = infoNode.get("dtype");
        DomainSpecificResponseType dsrType = null;
        try {
            dsrType = DomainSpecificResponseType.valueOf(dsrNodeTmp.textValue());
        } catch (Exception e) { ;
            return Optional.empty();
        }

        switch (dsrType) {
            case Connect:
                return new ConnectResponse().deserializeFrom(infoNode).map(DomainSpecificKernelResponse::new);

            case Register:
                return new RegisterResponse().deserializeFrom(infoNode).map(DomainSpecificKernelResponse::new);

            case GetAccounts:
                return new GetAccounts().deserializeFrom(infoNode).map(DomainSpecificKernelResponse::new);

            case GetActiveSessions:
                return new GetActiveSessions().deserializeFrom(infoNode).map(DomainSpecificKernelResponse::new);

            case Disconnect:
                return new DisconnectResponse().deserializeFrom(infoNode).map(DomainSpecificKernelResponse::new);

            case PeerList:
                return new PeerList().deserializeFrom(infoNode).map(DomainSpecificKernelResponse::new);
        }

        return Optional.empty();
    }
}
