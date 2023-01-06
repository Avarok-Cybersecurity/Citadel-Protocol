
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class AcceptPostRegisterHandler implements AbstractHandler {
  final u64 implicatedCid;
  final u64 peerCid;
  final String peerUsername;

  const AcceptPostRegisterHandler(this.implicatedCid, this.peerCid, this.peerUsername);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    // TODO: Change this once FCM accept-post-register ACK exists
    // For now, add the peer network account into the db
    PeerNetworkAccount(peerCid, implicatedCid, peerUsername).sync();
    return CallbackStatus.Complete;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("[AcceptPostRegister] ERR: ${kernelResponse.message}");
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    return CallbackStatus.Complete;
  }

}