package com.satori.deser.roottypes;

import com.satori.deser.DomainSpecificResponse;
import com.satori.deser.KernelResponse;
import com.satori.deser.KernelResponseType;
import com.satori.deser.Ticket;

import java.util.Optional;
import java.util.function.Consumer;

public class ErrorKernelResponse implements KernelResponse {
    private Optional<Ticket> ticket;
    private String message;
    private Consumer<KernelResponse> action = null;

    public ErrorKernelResponse(Optional<Ticket> ticket, String message) {
        this.ticket = ticket;
        this.message = message;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return this.ticket;
    }

    @Override
    public KernelResponseType getType() {
        return KernelResponseType.Error;
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