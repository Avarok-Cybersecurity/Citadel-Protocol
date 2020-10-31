package com.lusna.ffi.outbound;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class FFIPacket {

    public static final byte STD_COMMAND = 0;
    public static final byte[] LIST_ACCOUNTS_CMD = prepareFFIPacket("list-accounts", STD_COMMAND);
    public static final byte[] LIST_SESSIONS_CMD = prepareFFIPacket("list-sessions", STD_COMMAND);

    public static byte[] prepareFFIPacket(String command, byte cmdType) {
        byte[] asBytes = command.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(1 + asBytes.length);
        buf.put(cmdType);
        buf.put(asBytes);
        return buf.array();
    }

}
