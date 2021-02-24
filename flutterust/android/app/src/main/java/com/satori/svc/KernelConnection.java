package com.satori.svc;

public interface KernelConnection  {
    byte[] send_data(byte[] bytes);
    String start_rust_subsystem(byte[] homeDir, int kthreads);
    void ffiCallback(byte[] input);
}
