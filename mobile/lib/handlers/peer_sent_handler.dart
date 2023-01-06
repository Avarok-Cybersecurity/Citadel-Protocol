
import 'package:flutterust/components/chat_bubble.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/misc/message_send_handler.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/root/message_received.dart';

class PeerSendHandler extends AbstractHandler {
  final Optional<void Function(PeerSendUpdate)> onStatusUpdateReceived;
  final Optional<List<DefaultBubble>> bubbles;
  final Message message;

  PeerSendHandler._(this.onStatusUpdateReceived, this.message, this.bubbles);
  PeerSendHandler.screen(void Function(PeerSendUpdate) onStatusUpdateReceived, Message message, List<DefaultBubble> bubbles) : this._(Optional.of(onStatusUpdateReceived), message, Optional.of(bubbles));
  PeerSendHandler.screenless(Message message, Optional<List<DefaultBubble>> bubbles) : this._(Optional.empty(), message, bubbles);

  @override
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    print("PeerSendHandler: onConfirmation called");
    this.message.rawTicket = kernelResponse.getTicket().value.id;

    this.updateMessageState(PeerSendState.MessageSent);
    this.maybePushUIUpdate(PeerSendUpdate(PeerSendState.MessageSent, kernelResponse.getTicket(), this.message));
    return CallbackStatus.Pending;
  }

  @override
  void onErrorReceived(ErrorKernelResponse kernelResponse) {
    print("Error sending message: ${kernelResponse.message}");
    this.updateMessageState(PeerSendState.Failure);
    this.maybePushUIUpdate(PeerSendUpdate(PeerSendState.Failure, kernelResponse.getTicket(), this.message));
  }

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
    if (kernelResponse is MessageReceived) {
      print("PeerSendHandler: message has been verified to have been received!");
      await this.updateMessageState(PeerSendState.MessageReceived);

      this.maybePushUIUpdate(PeerSendUpdate(PeerSendState.MessageReceived, kernelResponse.getTicket(), this.message));
      return CallbackStatus.Complete;
    } else {
      if (AbstractHandler.validTypes(kernelResponse, DomainSpecificResponseType.FcmMessageReceived)) {
        print("[FCM] PeerSendHandler: message has been verified by FCM to have been received!");
        await this.updateMessageState(PeerSendState.MessageReceived);
        await MessageSendHandler.pollSpecificChannel(message, bubbles: this.bubbles.isPresent ? this.bubbles.value : null);
        this.maybePushUIUpdate(PeerSendUpdate(PeerSendState.MessageReceived, kernelResponse.getTicket(), this.message));
        return CallbackStatus.Complete;
      } else {
        print("[FCM] PeerSendHandler: Unexpected signal type: ${kernelResponse.getDSR()}");
        return CallbackStatus.Unexpected;
      }
    }
  }

  Future<void> updateMessageState(PeerSendState state) async {
    this.message.status = state;
    this.message.lastEventTime = DateTime.now();
    await message.sync();
  }

  void maybePushUIUpdate(PeerSendUpdate state) {
    if (this.onStatusUpdateReceived.isPresent) {
      this.onStatusUpdateReceived.value.call(state);
      return;
    }

    if (this.bubbles.isPresent) {
      // choose the right bubble
      try {
        DefaultBubble bubble = this.bubbles.value.reversed.firstWhere((element) => element.message.initTime.isAtSameMomentAs(this.message.initTime));
        if (bubble.callback.call(state)) {
          print("Success calling function updating $message");
        }
      } catch(_) {
        print("Could not find bubble in bubble list");
      }
    }
  }

}

class PeerSendUpdate {
  final PeerSendState state;
  final Optional<Ticket> ticket;
  final Message message;

  PeerSendUpdate(this.state, this.ticket, this.message);
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