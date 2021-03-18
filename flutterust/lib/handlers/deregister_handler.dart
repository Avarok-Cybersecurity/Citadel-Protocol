
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/deregister_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';

class DeregisterHandler extends AbstractHandler {
  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("[Deregister] Received error: ${kernelResponse.message}");
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.DeregisterResponse)) {
      print("[Deregister] Received valid type w/ ticket ${kernelResponse.getTicket().value}");
      DeregisterResponse dResp = kernelResponse.getDSR().value;
      if (dResp.success) {
        print("[Deregister] Deregistration success!");
        await PeerNetworkAccount.deletePeerByCid(dResp.implicatedCid, dResp.peerCid);
        EasyLoading.showSuccess("Deregistration from ${dResp.peerCid} success!", dismissOnTap: true);
      } else {
        print("[Deregister] Deregistration failed");
      }

      return CallbackStatus.Complete;
    } else {
      print("Unexpected type received: ${kernelResponse.getDSR()}");
      return CallbackStatus.Unexpected;
    }
  }

}