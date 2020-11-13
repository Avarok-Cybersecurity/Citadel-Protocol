package com.satori.deser.roottypes;

import com.satori.deser.DomainSpecificResponse;
import com.satori.deser.KernelResponse;
import com.satori.deser.KernelResponseType;
import com.satori.deser.Ticket;

import java.util.Optional;
import java.util.function.Consumer;

public class MessageKernelResponse implements KernelResponse {
    private final String message;
    private Consumer<KernelResponse> action = null;

    public MessageKernelResponse(String message) {
        this.message = message;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return Optional.empty();
    }

    @Override
    public KernelResponseType getType() {
        return KernelResponseType.Message;
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
        this.action = fx;
    }
}