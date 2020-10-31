package com.example.lusna;

import com.lusna.ffi.deser.DomainSpecificResponseType;
import com.lusna.ffi.deser.KernelResponse;
import com.lusna.ffi.deser.KernelResponseDeserializer;
import com.lusna.ffi.deser.domain.GetAccounts;
import com.lusna.ffi.deser.domain.GetActiveSessions;
import com.lusna.ffi.deser.domain.RegisterResponse;
import com.lusna.ffi.deser.roottypes.DomainSpecificKernelResponse;
import com.lusna.ffi.deser.roottypes.ErrorKernelResponse;
import com.lusna.ffi.deser.roottypes.HybridKernelResponse;
import com.lusna.ffi.deser.roottypes.MessageKernelResponse;
import com.lusna.util.ExponentialBackoffTracker;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    String messageTypeExample = "{\"type\":\"Message\",\"info\":\"Asynchronous kernel running. FFI Static is about to be set\"}";
    @Test
    public void messageTypeisCorrect() {
        System.out.println("Parsing: " + messageTypeExample);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(messageTypeExample).get();
        assert resp instanceof MessageKernelResponse;
        assertEquals(resp.getMessage().get(), "Asynchronous kernel running. FFI Static is about to be set");
        assert !resp.getDSR().isPresent();
        assert !resp.getTicket().isPresent();
        System.out.println("Success");
    }

    String hybridResponseTypeExample = "{\"type\":\"ResponseHybrid\",\"info\":[123, \"Hello world!\"]}";
    @Test
    public void hybridResponseTypeisCorrect() {
        System.out.println("Parsing: " + hybridResponseTypeExample);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(hybridResponseTypeExample).get();
        assert resp instanceof HybridKernelResponse;
        assertEquals(resp.getMessage().get(), "Hello world!");
        assert !resp.getDSR().isPresent();
        assertEquals(resp.getTicket().get().getValue(), 123);
        System.out.println("Success");
    }

    String ErrorTypeExample = "{\"type\":\"Error\",\"info\":[10,\"User nologik.test is already an active session ...\"]}";
    @Test
    public void errorTypeisCorrect() {
        System.out.println("Parsing: " + ErrorTypeExample);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(ErrorTypeExample).get();
        assert resp instanceof ErrorKernelResponse;
        assertEquals(resp.getMessage().get(), "User nologik.test is already an active session ...");
        assert !resp.getDSR().isPresent();
        assertEquals(resp.getTicket().get().getValue(), 10);
        System.out.println("Success");
    }

    String ErrorTypeExample2 = "{\"type\":\"Error\",\"info\":[0, \"Hello world (Error)!\"]}";
    @Test
    public void errorTypeIsCorrect2() {
        System.out.println("Parsing: " + ErrorTypeExample2);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(ErrorTypeExample2).get();
        assert resp instanceof ErrorKernelResponse;
        assertEquals(resp.getMessage().get(), "Hello world (Error)!");
        assert !resp.getDSR().isPresent();
        assert !resp.getTicket().isPresent();
        System.out.println("Success");
    }

    String DSRRegisterTypeExample = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Register\",\"Failure\":[2,\"Invalid username\"]}}";
    @Test
    public void DSRRegisterTypeIsCorrect() {
        System.out.println("Parsing: " + DSRRegisterTypeExample);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(DSRRegisterTypeExample).get();
        assert resp instanceof DomainSpecificKernelResponse;
        assertEquals(resp.getMessage().get(), "Invalid username");
        assert resp.getDSR().isPresent();
        assert resp.getDSR().get() instanceof RegisterResponse;
        assert !((RegisterResponse) resp.getDSR().get()).success;
        assert ((RegisterResponse) resp.getDSR().get()).getType() == DomainSpecificResponseType.Register;
        assertEquals(resp.getTicket().get().getValue(), 2);
        System.out.println("Success");
    }

    String DSRRegisterTypeExample2 = "{\"type\":\"DomainSpecificResponse\",\"info\": {\"dtype\":\"Register\",\"Success\":[2,\"Valid username\"]}}";
    @Test
    public void DSRRegisterTypeIsCorrect2() {
        System.out.println("Parsing: " + DSRRegisterTypeExample2);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(DSRRegisterTypeExample2).get();
        assert resp instanceof DomainSpecificKernelResponse;
        assertEquals(resp.getMessage().get(), "Valid username");
        assert resp.getDSR().isPresent();
        assert resp.getDSR().get() instanceof RegisterResponse;
        assert ((RegisterResponse) resp.getDSR().get()).success;
        assert ((RegisterResponse) resp.getDSR().get()).getType() == DomainSpecificResponseType.Register;
        assertEquals(resp.getTicket().get().getValue(), 2);
        System.out.println("Success");
    }

    String DSRgetAccounts = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"GetAccounts\",\"cids\":[2865279923,2865279924,2865279925,2865279926],\"usernames\":[\"nologik.test\",\"nologik.test2\",\"nologik.test3\",\"nologik.test4\"],\"full_names\":[\"thomas braun\",\"thomas braun2\",\"thomas braun\",\"thomas braun\"],\"is_personals\":[true,true,true,true],\"creation_dates\":[\"Thu Sep  3 20:43:12 2020\",\"Fri Sep  4 20:40:50 2020\",\"Mon Sep  7 01:22:46 2020\",\"Mon Sep  7 01:47:05 2020\"]}}";
    @Test
    public void DSRRgetAccountsTypeIsCorrect() {
        System.out.println("Parsing: " + DSRgetAccounts);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(DSRgetAccounts).get();
        assert resp instanceof DomainSpecificKernelResponse;
        assert !resp.getMessage().isPresent();
        assert resp.getDSR().isPresent();
        assert resp.getDSR().get() instanceof GetAccounts;
        assert resp.getDSR().get().getType() == DomainSpecificResponseType.GetAccounts;
        assert !resp.getTicket().isPresent();
        GetAccounts accounts = (GetAccounts) resp.getDSR().get();
        assertEquals(accounts.cids.size(), 4);
        for (int i = 0; i < accounts.cids.size(); i++) {
            System.out.println(accounts.getAccountByIndex(i).get());
        }
        System.out.println("Success");
    }

    String DSRlistSessions = "{\"type\":\"DomainSpecificResponse\",\"info\":{\"dtype\":\"GetActiveSessions\",\"usernames\":[\"nologik.test4\", \"nologik.test5\"],\"cids\":[2865279926, 123456789],\"ips\":[\"51.81.35.200\", \"51.81.35.201\"],\"is_personals\":[true, false],\"runtime_sec\":[8, 1000]}}";

    @Test
    // usernames: Vec<String>,
    // cids: Vec<u64>,
    // ips: Vec<String>,
    // is_personals: Vec<bool>,
    // runtime_sec: Vec<u64>
    public void DSRGetSessionsTypeIsCorrect() {
        System.out.println("Parsing: " + DSRlistSessions);
        KernelResponse resp = KernelResponseDeserializer.tryFrom(DSRlistSessions).get();
        assert resp instanceof DomainSpecificKernelResponse;
        assert !resp.getMessage().isPresent();
        assert resp.getDSR().isPresent();
        assert resp.getDSR().get() instanceof GetActiveSessions;
        assert resp.getDSR().get().getType() == DomainSpecificResponseType.GetActiveSessions;
        assert !resp.getTicket().isPresent();
        GetActiveSessions accounts = (GetActiveSessions) resp.getDSR().get();
        assertEquals(accounts.cids.size(), 2);
        for (int i = 0; i < accounts.cids.size(); i++) {
            System.out.println(accounts.getAccountByIndex(i).get());
        }
        System.out.println("Success");
    }

    @Test
    public void exponentialBackoffFails() {
        AtomicInteger i = new AtomicInteger(0);
        // 100, 200, 400, 800, 1600, 3200
        ExponentialBackoffTracker exec = new ExponentialBackoffTracker(100, 3000, () -> i.getAndAdd(1) > 5);

        while (!exec.revolution());
        assert !exec.didSucceed();
    }

    @Test
    public void exponentialBackoffSucceeds() {
        AtomicInteger i = new AtomicInteger(0);
        // 100 (0), 200 (1) , 400 (2), 800 (3), 1600 (4), 3200
        ExponentialBackoffTracker exec = new ExponentialBackoffTracker(100, 3000, () -> i.getAndAdd(1) > 3);

        while (!exec.revolution());
        assert exec.didSucceed();
    }
}