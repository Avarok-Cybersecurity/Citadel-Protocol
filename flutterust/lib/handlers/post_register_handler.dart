
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/utils.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_response.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class PostRegisterHandler implements AbstractHandler {
  final u64 peerCid;

  PostRegisterHandler(this.peerCid);

  @override
  void onConfirmation(KernelResponse kernelResponse) {}

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("[PostRegisterHandler] Error received: " + kernelResponse.message);
  }

  @override
  void onTicketReceived(KernelResponse kernelResponse) {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.PostRegisterResponse)) {
      PostRegisterResponse resp = kernelResponse.getDSR().value;
      print(this.peerCid.toString() + " accepted? " + resp.accept.toString());
      String message = resp.accept ? resp.username + " accepted your request" : this.peerCid.toString() + " did not consent to registering at this time";
      Utils.pushNotification("Register request " + this.peerCid.toString(), message);
    } else {
      print("Invalid DSR type!");
    }
  }

}