/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

package org.hyxewave.connect;

import io.vertx.core.Vertx;
import io.vertx.core.datagram.DatagramSocket;
import io.vertx.core.datagram.DatagramSocketOptions;
import org.hyxewave.gui.HyxeWaveDesktopEnvironment;
import org.hyxewave.util.Constants;
import org.hyxewave.util.DaemonParser;

import java.util.ArrayList;

public class AsyncLoopbackClient {

    private Vertx vertx;
    private DatagramSocket socket;
    private HyxeWaveDesktopEnvironment gui;
    private ArrayList<Expectancy> sendMap = new ArrayList<>();

    public AsyncLoopbackClient(HyxeWaveDesktopEnvironment gui) {
        this.vertx = Vertx.vertx();

        this.socket = this.vertx.createDatagramSocket(new DatagramSocketOptions().setReuseAddress(true));
        this.gui = gui;

        this.socket.listen(0, "127.0.0.1", asyncResult -> {
            if (asyncResult.succeeded()) {
                socket.handler(packet -> {
                    System.out.println("DATA_RECV+IN " + packet.data().toString());
                    if (packet.sender().host().equals("0.0.0.0") || packet.sender().host().equals("127.0.0.1"))
                        this.forwardPacketToClosure(DaemonParser.parseInboundData(packet.data().toString()));


                });
            } else {
                System.out.println("Listen failed" + asyncResult.cause());
            }
        });
    }

    public void send(Command cmd, String data, long eid) {
        System.out.println("[Async] Received outbound data");
        socket.send(prepare_outbound_data(cmd, data), Constants.DAEMON_PORT, "127.0.0.1", asyncResult -> {
            if (asyncResult.succeeded()) {
                sendMap.add(new Expectancy(eid, System.currentTimeMillis(), (exp, packet, instant, did_timeout) -> {
                    System.out.println("Expectancy " + exp.eid + " executing...");
                    if (!did_timeout) {
                        System.out.println("[Async Expectancy] EID fulfilled!");
                        //push to GUI/VirtualDesktop
                        this.gui.onResponseReceived(packet, this.vertx, false);
                        return true;
                    }

                    System.err.println("[Async] Timeout for expectancy " + exp.eid + " reached");
                    this.gui.onResponseReceived(null, null, true);
                    return false;
                }));


                vertx.setTimer(Constants.TIMEOUT, (e) -> {
                    for (Expectancy exp : this.sendMap) {
                        if (exp.eid == eid) {
                            if (exp.did_timeout) {
                                System.err.println("[Async Expectancy] Timeout reached for eid " + eid);
                                this.sendMap.remove(exp);
                                exp.onPacketReceived.operation(exp, null, System.currentTimeMillis(), true);
                            }
                            return;
                        }
                    }
                });
            }
            System.out.println("Send succeeded? " + asyncResult.succeeded());
        });
    }

    private void forwardPacketToClosure(DaemonParser.DaemonPacket packet) {
        for (Expectancy exp : this.sendMap) {
            if ((exp.eid + "").equals(packet.eid)) {
                this.sendMap.remove(exp);
                long time_received = System.currentTimeMillis();
                boolean did_timeout = false;
                if (time_received - exp.timestamp_out >= Constants.TIMEOUT) {
                    did_timeout = true;
                }

                if (!did_timeout) exp.did_timeout = false;

                exp.onPacketReceived.operation(exp, packet, time_received, did_timeout);
                return;
            }
        }

        System.out.println("[Async] Packet received with no expectancy. Treating as a signal...");
        handle_signal(packet);
    }

    private void handle_signal(DaemonParser.DaemonPacket packet) {
        this.gui.onSignalReceived(packet, vertx);
    }

    private String prepare_outbound_data(Command cmd, String data) {
        return "[" + cmd.toString() + "]" + data;
    }

    public enum Command {
        CONNECT, SEND_MESSAGE, SEND_FILE
    }

    protected interface OneArgInterface {
        boolean operation(Expectancy exp, DaemonParser.DaemonPacket packet, long instant, boolean did_timeout);
    }

    private class Expectancy {
        protected long eid;
        protected long timestamp_out;
        protected OneArgInterface onPacketReceived;

        protected boolean did_timeout = true; //start off as true, can only be toggled back once a packet comes in matching the eid herein

        protected Expectancy(long eid, long timestamp_out, OneArgInterface onPacketReceived) {
            this.eid = eid;
            this.timestamp_out = timestamp_out;
            this.onPacketReceived = onPacketReceived;
        }
    }
}
