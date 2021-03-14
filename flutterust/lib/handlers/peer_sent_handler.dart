
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

class PeerSendHandler extends AbstractHandler {
  final void Function(PeerSendUpdate) onStatusUpdateReceived;
  final int messageIdxInChat;

  PeerSendHandler(this.onStatusUpdateReceived, this.messageIdxInChat);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    this.onStatusUpdateReceived.call(PeerSendUpdate(PeerSendState.MessageSent, kernelResponse.getTicket(), this.messageIdxInChat));
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("Error sending message: ${kernelResponse.message}");
    this.onStatusUpdateReceived.call(PeerSendUpdate(PeerSendState.Failure, kernelResponse.getTicket(), this.messageIdxInChat));
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.FcmMessageReceived)) {
      print("[FCM] PeerSendHandler: message has been verified by FCM to have been received!");
      this.onStatusUpdateReceived.call(PeerSendUpdate(PeerSendState.MessageReceived, kernelResponse.getTicket(), this.messageIdxInChat));
      return CallbackStatus.Complete;
    } else {
      print("[FCM] PeerSendHandler: Unexpected signal type: ${kernelResponse.getDSR()}");
      return CallbackStatus.Unexpected;
    }
  }

}

class PeerSendUpdate {
  final PeerSendState state;
  final Optional<Ticket> ticket;
  final int messageIdxInChat;

  PeerSendUpdate(this.state, this.ticket, this.messageIdxInChat);
}

enum PeerSendState {
  MessageSent,
  MessageReceived,
  Failure
}