package com.lusna.ffi.deser.roottypes;

import androidx.annotation.Nullable;

import com.lusna.ffi.deser.DomainSpecificResponse;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.KernelResponseType;
import com.lusna.ffi.Ticket;

import java.util.Optional;
import java.util.function.Consumer;

public class MessageKernelResponse implements KernelResponse {
    private String message;
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