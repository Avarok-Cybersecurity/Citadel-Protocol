package com.satori.deser.roottypes;

import com.satori.deser.DomainSpecificResponse;
import com.satori.deser.KernelResponse;
import com.satori.deser.KernelResponseType;
import com.satori.deser.Ticket;

import java.util.Optional;
import java.util.function.Consumer;

public class ConfirmationKernelResponse implements KernelResponse {
    private Consumer<KernelResponse> action = null;
    @Override
    public Optional<Ticket> getTicket() {
        return Optional.empty();
    }

    @Override
    public KernelResponseType getType() {
        return KernelResponseType.Confirmation;
    }

    @Override
    public Optional<String> getMessage() {
        return Optional.empty();
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