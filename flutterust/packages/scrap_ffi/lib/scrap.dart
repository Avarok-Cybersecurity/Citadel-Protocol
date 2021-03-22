import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:tuple/tuple.dart';
import 'package:optional/optional.dart';

import 'ffi.dart' as native;

class FFIBridge {

  final MethodChannel toJava = const MethodChannel('com.satori.verisend/native');
  String fcmToken = "";

  static setup() {
    native.store_dart_post_cobject(NativeApi.postCObject);
    print("FFI post-cobject loaded");
  }

  Isolate isolate;

  void sendToBackground() {
    if (Platform.isAndroid) {
      toJava.invokeMethod("sendToBackground");
    }
  }

  Future<void> initRustSubsystem(void Function(String ffiPacket) onPacketReceived) async {
    print("Calling initRustSubsystem");
    ReceivePort port = ReceivePort();
    SendPort rustComsPort = port.sendPort;
    String path = await localPath();

    print("Loaded directory: " + path);
    var input = Tuple2(rustComsPort, path);
    isolate = await Isolate.spawn(ffiInitRustSubsystem, input);
    // the below will be called, non-blocking the primary gui isolate calling this function
    port.listen((ffiPacket) {
      // ffiPacket is type Vec<u8>, or Uint8List in dart
      Uint8List packet = ffiPacket;
      String jsonPacket = Utf8Decoder().convert(packet);
      print("Received FFI Packet (len: " + packet.length.toString() + "): " + jsonPacket);
      onPacketReceived(jsonPacket);
    }, onDone: () {
      print("Rust subsystem disconnected!");
      exit(-1);
    });
  }

  Future<String> localPath() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }

  static void ffiInitRustSubsystem(Tuple2<SendPort, String> initInput) {
    String homeDir = initInput.item2;
    int port = initInput.item1.nativePort;
    Pointer<Utf8> dirPtr = homeDir.toNativeUtf8();
    // pass the port and pointer to the ffi frontier
    int initResult = native.load_page(port, dirPtr);
    print("Done setting up rust subsystem. Result: " + initResult.toString());
    // now, the rust subsystem is running. The function that calls ffiInitRustSubsystem will handle to inbound messages
    // sent from rust
  }

  /// Executes the given command, then passing the kernel response string into visitor.
  /// Thereafter, cleans up the memory to prevent memory leaks
  Future<Optional<KernelResponse>> executeCommand(String cmd) async {
    String resp = await this.sendToKernel(cmd);
    print("FFI-Dart Recv: " + resp);
    var kernelResponse = FFIParser.tryFrom(resp);
    this.memfree(resp);
    return kernelResponse;
  }

  Future<String> sendToKernel(String cmd) async {
    Pointer<Utf8> ptr = cmd.toNativeUtf8();
    return native.send_to_kernel(ptr).toDartString();
  }

  Future<Optional<KernelResponse>> handleFcmMessage(String rawPayload) async {
    rawPayload.toNativeUtf8();
    Pointer<Utf8> ptr = rawPayload.toNativeUtf8();
    Pointer<Utf8> dirPtr = (await this.localPath()).toNativeUtf8();
    return FFIParser.tryFrom(native.fcm_process(ptr, dirPtr).toDartString());
  }

  void memfree(String ptr) {
    if (!Platform.isAndroid) {
      native.memfree(ptr.toNativeUtf8());
    }
  }

  bool isKernelLoaded() {
    return native.is_kernel_loaded() == 1;
  }
}
