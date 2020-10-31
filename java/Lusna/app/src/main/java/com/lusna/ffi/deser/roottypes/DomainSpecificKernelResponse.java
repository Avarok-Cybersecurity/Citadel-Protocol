package com.lusna.ffi.deser.roottypes;

import androidx.annotation.Nullable;

import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.KernelResponseType;
import com.lusna.ffi.Ticket;

import java.util.Optional;
import java.util.function.Consumer;

public class DomainSpecificKernelResponse<T extends DomainSpecificResponse> implements KernelResponse {
    private T dsr;
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