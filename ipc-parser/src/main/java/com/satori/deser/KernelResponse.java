package com.satori.deser;

import java.util.Optional;
import java.util.function.Consumer;

public interface KernelResponse {
    Optional<Ticket> getTicket();
    KernelResponseType getType();
    Optional<String> getMessage();
    Optional<DomainSpecificResponse> getDSR();
    Optional<Consumer<KernelResponse>> getCallbackAction();

    void setCallbackAction(Consumer<KernelResponse> fx);
    /*
    default Optional<Consumer<KernelResponse>> getCallbackAction() {
        Consumer<KernelResponse> kCallback = this.getCallbackActionRaw();
        if (kCallback != null) {
            return Optional.of(kCallback);
        } else {
            return Optional.empty();
        }
    }*/
}