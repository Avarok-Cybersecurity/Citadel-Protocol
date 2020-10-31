package com.lusna.ffi.deser.roottypes;

import androidx.annotation.Nullable;

import com.lusna.ffi.Ticket;
import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.KernelResponseType;

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