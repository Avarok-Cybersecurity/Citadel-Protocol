
import 'package:flutterust/database/message.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/root/message_received.dart';

class PeerSendHandler extends AbstractHandler {
  final void Function(PeerSendUpdate) onStatusUpdateReceived;
  final int messageIdxInChat;
  final Message message;

  PeerSendHandler(this.onStatusUpdateReceived, this.message, this.messageIdxInChat);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    print("PeerSendHandler: onConfirmation called");
    this.message.rawTicket = kernelResponse.getTicket().value.id;

    this.updateMessageState(PeerSendState.MessageSent);
    this.onStatusUpdateReceived.call(PeerSendUpdate(PeerSendState.MessageSent, kernelResponse.getTicket(), this.message, this.messageIdxInChat));
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("Error sending message: ${kernelResponse.message}");
    this.updateMessageState(PeerSendState.Failure);
    this.onStatusUpdateReceived.call(PeerSendUpdate(PeerSendState.Failure, kernelResponse.getTicket(), this.message, this.messageIdxInChat));
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (kernelResponse is MessageReceived) {
      print("PeerSendHandler: message has been verified to have been received!");
      await this.updateMessageState(PeerSendState.MessageReceived);

      this.onStatusUpdateReceived.call(PeerSendUpdate(PeerSendState.MessageReceived, kernelResponse.getTicket(), this.message, this.messageIdxInChat));
      return CallbackStatus.Complete;
    } else {
      if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.FcmMessageReceived)) {
        print("[FCM] PeerSendHandler: message has been verified by FCM to have been received!");
        await this.updateMessageState(PeerSendState.MessageReceived);

        this.onStatusUpdateReceived.call(PeerSendUpdate(PeerSendState.MessageReceived, kernelResponse.getTicket(), this.message, this.messageIdxInChat));
        return CallbackStatus.Complete;
      } else {
        print("[FCM] PeerSendHandler: Unexpected signal type: ${kernelResponse.getDSR()}");
        return CallbackStatus.Unexpected;
      }
    }
  }

  Future<void> updateMessageState(PeerSendState state) async {
    this.message.status = state;
    await message.sync();
  }

}

class PeerSendUpdate {
  final PeerSendState state;
  final Optional<Ticket> ticket;
  final int messageIdxInChat;
  final Message message;

  PeerSendUpdate(this.state, this.ticket, this.message, this.messageIdxInChat);
}

enum PeerSendState {
  Unprocessed,
  MessageSent,
  MessageReceived,
  Failure
}

extension PeerSendStateExt on PeerSendState {

  static Optional<PeerSendState> fromString(String type) {
    try {
      return Optional.of(PeerSendState.values.firstWhere((element) => element.toString().split('.').last == type));
    } catch(_) {
      return Optional.empty();
    }
  }

  String asString() {
    return this.toString().split(".").last;
  }
}