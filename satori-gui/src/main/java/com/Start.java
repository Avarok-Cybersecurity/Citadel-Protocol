package com;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.Vertx;

import io.vertx.core.net.SocketAddress;

public class Start extends AbstractVerticle {

    private static final SocketAddress LOCAL_SOCKET = SocketAddress.inetSocketAddress(25022, "0.0.0.0");

    public static void main(String... args) {
        Vertx.vertx().deployVerticle(new Start());
    }

    @Override
    public void start() throws Exception {
        super.start();
        vertx.createNetClient().connect(LOCAL_SOCKET, event -> {
            System.out.println("Connection success ? " + event.succeeded());
        });
    }
}
