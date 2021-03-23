import 'dart:async';

import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/main.dart';
import 'package:satori_ffi_parser/result.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/get_active_sessions.dart';
import 'package:satori_ffi_parser/types/dsr/peer_mutuals.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/u64.dart';

extension IsConnected on u64 {

  Future<bool> isLocallyConnected() async {
    return await RustSubsystem.bridge!.executeCommand("list-sessions")
        .then((value) => value.map((resp) => resp.getDSR().cast<GetSessionsResponse>().map((peerListResponse) {
      return peerListResponse.cids.contains(this);
    }).orElse(false)).orElse(false));
  }

  /// 'This' is implicated cid
  Future<bool> isMutualPeerConnected(u64 peerCid) async {
    StreamController<Result<bool, String>> recv = StreamController();
    var res = await RustSubsystem.bridge!.executeCommand("switch $this peer mutuals")
        .then((value) => value.map((kResp) {
      KernelResponseHandler.handleFirstCommand(kResp, handler: CustomPeerMutualsHandler(peerCid, recv.sink), oneshot: false);
      return true;
    }).orElse(false));

    if (res) {
      return await recv.stream.first.then((value) async {
        await recv.close();
        return value == Result.ok(true);
      });

    } else {
      await recv.close();
      return false;
    }
  }


  // If the client is either online through the standard protocol, or, can be reached via FCM, then this will return true
  static bool isOnline(u64 cid, List<u64> cids, List<bool> isOnlines, {List<bool>? isFcmReachable}) {
    var idx = cids.indexWhere((element) => element == cid);
    if (idx != -1) {
      return isOnlines[idx] || (isFcmReachable != null ? isFcmReachable[idx] : false);
    } else {
      return false;
    }
  }
}

class CustomPeerMutualsHandler implements AbstractHandler {
  final u64 peerCid;
  final StreamSink<Result<bool, String>> sink;

  CustomPeerMutualsHandler(this.peerCid, this.sink);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("[PeerMutualsExt] ERR: ${kernelResponse.message}");
    sink.add(Result.err(kernelResponse.message));
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.PeerMutuals)) {
      PeerMutualsResponse resp = kernelResponse.getDSR().value as PeerMutualsResponse;
      sink.add(Result.ok(IsConnected.isOnline(this.peerCid, resp.cids, resp.isOnlines)));
      return CallbackStatus.Complete;
    } else {
      print("[PeerMutualsExt] unexpected kernel response");
      return CallbackStatus.Unexpected;
    }
  }


}