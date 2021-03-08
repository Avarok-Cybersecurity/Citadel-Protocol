import 'dart:isolate';

import 'package:flutter/cupertino.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:quiver/iterables.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/peer_mutuals.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:flutterust/database/abstract_sql_object.dart';

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
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.PeerMutuals)) {
      PeerMutualsResponse peerMutuals = kernelResponse.getDSR().value;
      List<PeerNetworkAccount> peers = zip([peerMutuals.cids, peerMutuals.usernames]).map((e) => PeerNetworkAccount(e[0], peerMutuals.implicated_cid, e[1])).toList(growable: false);
      var list = await peers.upsert();
      print("[database result] $list");

      this.sendPort.send(peerMutuals);
    } else {
      print("Invalid DSR type!");
    }

    return CallbackStatus.Complete;
  }

}