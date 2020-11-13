package com.satori.deser.roottypes;

import com.satori.deser.DomainSpecificResponse;
import com.satori.deser.KernelResponse;
import com.satori.deser.KernelResponseType;
import com.satori.deser.Ticket;

import java.util.Optional;
import java.util.function.Consumer;

public class DomainSpecificKernelResponse<T extends DomainSpecificResponse> implements KernelResponse {
    private final T dsr;
    private Consumer<KernelResponse> action = null;

    public DomainSpecificKernelResponse(T dsr) {
        this.dsr = dsr;
    }

    @Override
    public Optional<Ticket> getTicket() {
        return this.dsr.getTicket();
    }

    @Override
    public KernelResponseType getType() {
        return KernelResponseType.DomainSpecificResponse;
    }

    @Override
    public Optional<String> getMessage() {
        return this.dsr.getMessage();
    }

    @Override
    public Optional<DomainSpecificResponse> getDSR() {
        return Optional.of(this.dsr);
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