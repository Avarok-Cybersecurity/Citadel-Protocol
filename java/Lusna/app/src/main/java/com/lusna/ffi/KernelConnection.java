package com.lusna.ffi;

public interface KernelConnection  {
    byte[] send_data(byte[] bytes);
    String start_rust_subsystem(byte[] homeDir);
    void ffiCallback(byte[] input);
}
