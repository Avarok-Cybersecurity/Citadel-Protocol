
import 'dart:async';

import 'package:flutter/cupertino.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/peer_list.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';

import '../utils.dart';

class PeerListHandler implements AbstractHandler {
  final BuildContext context;
  final void Function(DomainSpecificResponse) onResult;

  PeerListHandler(this.context, this.onResult);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    Utils.popup(this.context, "Unable to retrieve peers", kernelResponse.message);
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.PeerList)) {
      PeerListResponse peerList = kernelResponse.getDSR().value as PeerListResponse;
      this.onResult.call(peerList);
    } else {
      print("Invalid DSR type!");
    }

    return CallbackStatus.Complete;
  }

}