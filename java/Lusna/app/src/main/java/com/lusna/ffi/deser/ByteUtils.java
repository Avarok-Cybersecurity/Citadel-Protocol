package com.lusna.ffi.deser;

import java.nio.ByteBuffer;

// synchronized to ensure two writes to the buffer don't happen at once
public class ByteUtils {
    private static ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);

    public synchronized static byte[] longToBytes(long x) {
        buffer.putLong(0, x);
        return buffer.array();
    }

    public synchronized static long bytesToLong(byte[] bytes) {
        buffer.put(bytes, 0, Long.BYTES);
        buffer.flip();//need flip
        return buffer.getLong();
    }
}