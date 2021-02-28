
import 'dart:isolate';

import 'package:flutter/cupertino.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/peer_list.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';

import '../utils.dart';

class PeerListHandler implements AbstractHandler {
  final BuildContext context;
  final SendPort sendPort;

  PeerListHandler(this.context, this.sendPort);

  @override
  void onConfirmation(KernelResponse kernelResponse) {}

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    Utils.popup(this.context, "Unable to retrieve peers", kernelResponse.message);
  }

  @override
  CallbackStatus onTicketReceived(KernelResponse kernelResponse) {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.PeerList)) {
      PeerListResponse peerList = kernelResponse.getDSR().value;
      this.sendPort.send(peerList);
    } else {
      print("Invalid DSR type!");
    }

    return CallbackStatus.Complete;
  }

}