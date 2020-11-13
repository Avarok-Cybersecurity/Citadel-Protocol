package com.satori.deser;

import com.satori.util.ByteUtils;

import java.util.Optional;

public class Ticket {
    // Must be a nonzero field value
    private final long ticket;
    public Ticket(long ticket) {
        this.ticket = ticket;
    }

    public static Optional<Ticket> tryFrom(long ticket) {
        if (ticket != 0) {
            return Optional.of(new Ticket(ticket));
        } else {
            return Optional.empty();
        }
    }

    public static Optional<Ticket> tryFromBytes(byte[] payload) {
        if (payload.length > 8) {
            return Ticket.tryFrom(ByteUtils.bytesToLong(payload));
        } else {
            return Optional.empty();
        }
    }

    public long getValue() {
        return this.ticket;
    }

    public Optional<Long> getTicket() {
        if (this.ticket != 0) {
            return Optional.of(this.ticket);
        } else {
            return Optional.empty();
        }
    }
}
