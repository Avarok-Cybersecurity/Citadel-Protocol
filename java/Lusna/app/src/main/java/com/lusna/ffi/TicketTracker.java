package com.lusna.ffi;

import androidx.annotation.NonNull;

import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.KernelResponseDeserializer;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class TicketTracker {
    // TODO investigate: While all outbound requests sent by the LOCAL kernel's HdpServerRemote are guaranteed to produce
    // sequentially unique Ticket ID's, it is possible that the other end will produce Ticket id's
    // with values that have already used values locally. If such a ticket ID exists in the hashmap below,
    // then there can exist a COLLISION. This is not good. However, the chances of the are pretty small, but can nonetheless
    // cause dysfunction.
    public static ConcurrentHashMap<Long, KernelResponse> map = new ConcurrentHashMap<>();

    /// Immediately after receiving FFI input, this function should be called (on a sovereign thread)
    public static void onResponseReceived(@NonNull KernelConnection kConn, byte[] input) {
        String response = new String(input, StandardCharsets.UTF_8);
        System.out.println("Resp: " + response);
        Optional<KernelResponse> kernelResponse = KernelResponseDeserializer.tryFrom(response);
        if (kernelResponse.isPresent()) {
            KernelResponse kResp = kernelResponse.get();
            Optional<Ticket> ticketOptional = kResp.getTicket();
            if (ticketOptional.isPresent()) {
                Ticket ticket = ticketOptional.get();
                KernelResponse previous = map.remove(ticket.getValue());
                if (previous != null) {
                    // execute the function, passing in the new response
                    previous.getCallbackAction().ifPresent((fx) -> fx.accept(kResp));
                } else {
                    System.out.println("The provided ticket " + ticket.getValue() + " did not map to a value in the hashmap");
                    // There is no ticket, but there may be vital information, such as a vital disconnect or a peer request
                    UntrackedKernelResponseHandler.handleUntrackedMessage(kResp, kConn);
                }
            } else {
                // There is no ticket, but there may be vital information, such as a vital disconnect or a peer request
                UntrackedKernelResponseHandler.handleUntrackedMessage(kResp, kConn);
            }
        } else {
            System.out.println("kernel response is Empty. Bad packet?");
        }
    }

    public static void insert(Ticket ticket, KernelResponse resp) {
        map.put(ticket.getValue(), resp);
    }
}
