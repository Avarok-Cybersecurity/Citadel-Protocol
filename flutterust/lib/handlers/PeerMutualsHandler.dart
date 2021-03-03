import 'dart:isolate';

import 'package:flutter/cupertino.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/peer_mutuals.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';

import '../utils.dart';

class PeerMutualsHandler implements AbstractHandler {
  final BuildContext context;
  final SendPort sendPort;

  PeerMutualsHandler(this.context, this.sendPort);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    Utils.popup(this.context, "Unable to retrieve mutuals", kernelResponse.message);
  }

  @override
  CallbackStatus onTicketReceived(KernelResponse kernelResponse) {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.PeerMutuals)) {
      PeerMutualsResponse peerMutuals = kernelResponse.getDSR().value;
      this.sendPort.send(peerMutuals);
    } else {
      print("Invalid DSR type!");
    }

    return CallbackStatus.Complete;
  }

}