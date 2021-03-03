import 'dart:isolate';

import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/screens/login.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';

class LoginHandler implements AbstractHandler {
  final SendPort port;
  final String username;

  LoginHandler(this.port, this.username);

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("[Login Handler] Login failed: " + kernelResponse.message);
    this.port.send(LoginUISignal(LoginUpdateSignalType.LoginFailure, message: kernelResponse.message));
  }

  @override
  CallbackStatus onTicketReceived(KernelResponse kernelResponse) {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.Connect)) {
      ConnectResponse resp = kernelResponse.getDSR().value;
      if (resp.success) {
        print("[Login Handler] SUCCESS!");
        resp.attachUsername(this.username);
        this.port.send(LoginUISignal(LoginUpdateSignalType.LoginSuccess, message: kernelResponse.getMessage().orElse("Successfully connected!")));
        SessionHomeScreenInner.sendPort.send(resp);
      } else {
        this.onErrorReceived(kernelResponse);
      }
    } else {
      print("Invalid DSR type!");
    }

    return CallbackStatus.Complete;
  }

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }


}