
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/utils.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_request.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_response.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class PostRegisterHandler implements AbstractHandler {
  final u64 peerCid;

  PostRegisterHandler(this.peerCid);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    EasyLoading.showInfo("Request sent. Please wait for the user to confirm ...", dismissOnTap: true);
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) async {
    print("[PostRegisterHandler] Error received: " + kernelResponse.message);
    await EasyLoading.showError(kernelResponse.message, dismissOnTap: true);
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.PostRegisterResponse)) {
      PostRegisterResponse resp = kernelResponse.getDSR().value as PostRegisterResponse;

      print(this.peerCid.toString() + " accepted? " + resp.accept.toString());
      String message = resp.accept ? resp.username + " accepted your request" : this.peerCid.toString() + " did not consent to registering at this time";
      // TODO: Create PostRegisterResponsePushNotification
      Utils.pushNotification("Register request " + this.peerCid.toString(), message);
      RustSubsystem.bridge?.executeCommand("ticket remove ${resp.ticket.id}");

      if (resp.accept) {
        await PeerNetworkAccount(this.peerCid, resp.implicatedCid, resp.username).sync();
      }

      return CallbackStatus.Complete;
    } else {
      print("[Post-register] DSR type not yet what's required ...");
      if (kernelResponse.getDSR().isPresent) {
        if (kernelResponse.getDSR().value is PostRegisterRequest) {
          print("[DEBUG] received PostRegisterInvitation type, implying the initiator and recipient on the same node");
          return CallbackStatus.Unexpected;
        }
      }

      return CallbackStatus.Pending;
    }
  }
}