import 'dart:isolate';

import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';

class LoginHandler implements AbstractHandler {
  final SendPort port;
  final String username;

  LoginHandler(this.port, this.username);

  @override
  void onErrorReceived(KernelResponse kernelResponse) {
    print("[Login Handler] Login failed: " + kernelResponse.getMessage().value);
    this.port.send(LoginUISignal(LoginUpdateSignalType.LoginFailure, message: kernelResponse.getMessage().orElse("Unable to connect (unknown)")));
  }

  @override
  void onTicketReceived(KernelResponse kernelResponse) {
    ConnectResponse resp = kernelResponse.getDSR().value;
    if (resp.success) {
      print("[Login Handler] SUCCESS!");
      resp.attachUsername(this.username);
      this.port.send(LoginUISignal(LoginUpdateSignalType.LoginSuccess, message: kernelResponse.getMessage().orElse("Successfully connected!")));
      SessionHomeScreenInner.sendPort.send(resp);
    } else {
      this.onErrorReceived(kernelResponse);
    }
  }

  @override
  void onConfirmation(KernelResponse kernelResponse) {}

}