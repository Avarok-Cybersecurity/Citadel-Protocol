import 'dart:collection';

import 'package:flutterust/database_handler.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/utils.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/kernel_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_request.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/root/node_message.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

class KernelResponseHandler {
  static final pendingTickets = HashMap<Ticket, KernelResponse>();

  /// When sending a command to the kernel, the kernel will immediately respond. This should be called
  /// `oneshot`: If oneshot is left as default, then once the ticket's callback is triggered, the callback will never again be called.
  /// If set to false, then an inbound ticket can indefinitely trigger the callback, so long as the callback continues to exist (useful for peer channels, groups, file-transfers, etc)
  static void handleFirstCommand(KernelResponse kernelResponse, { AbstractHandler handler = const DefaultHandler(), bool oneshot = true}) {
    kernelResponse.setCallbackAction(handler.onTicketReceived); // by DEFAULT, this runs when handleRustKernelMessage executes

    // TODO: Handle DSRs, as we get results on first command response
    switch (kernelResponse.getType()) {
      case KernelResponseType.ResponseTicket:
      case KernelResponseType.ResponseHybrid:
        pendingTickets.putIfAbsent(kernelResponse.getTicket().value, () => kernelResponse);
        handler.onConfirmation(kernelResponse);
        break;

      case KernelResponseType.Error:
        handler.onErrorReceived(kernelResponse as ErrorKernelResponse);
        break;
    }
  }

  // FFI packets get sent here when the rust kernel sends messages
  static void handleRustKernelRawMessage(String ffiPacket) {
    FFIParser.tryFrom(ffiPacket)
        .ifPresent(handleRustKernelMessage, orElse: () {
          print("Unable to decode FFI Packet: " + ffiPacket);
    });
  }

  static void handleRustKernelMessage(KernelResponse message) async {
    print("Received valid kernel message");
    // Essentially, any delayed response that has a ticket should be handled via the stored callbacks inside pendingTickets
    if (message.getTicket().isPresent) {
      var entry = pendingTickets[message.getTicket().value];
      if (entry != null) {
        if (entry.isOneshot()) {
          pendingTickets.remove(message.getTicket().value);
        }

        print("Pre-existing entry for " + message.getTicket().value.toString() + " found, will maybe trigger callback");
        var callback = entry.getCallbackAction();
        if (callback.isPresent) {
          switch (callback.value(message)) {
            case CallbackStatus.Complete:
              pendingTickets.remove(message.getTicket().value);
              break;

            default:
          }
        } else {
          print("No callback registered");
        }
      } else {
        print("Ticket " + message.getTicket().value.toString() + " did not map to an expected kernel response. Maybe relevant");

        if (message.getType() == KernelResponseType.NodeMessage) {
          NodeMessageKernelResponse resp = message;
          String username = (await ClientNetworkAccount.getUsernameByCid(resp.cid)).value;
          // TODO: map CIDs to Usernames
          Utils.pushNotification("Message for " + username, resp.message);
        }
      }
    } else {
      // no ticket present; we don't interact with the message through callbacks. We need another way to handle these messages
      // if message type, send to session + notification
      handleUnexpectedSignal(message);
    }
  }

  static void handleUnexpectedSignal(KernelResponse message) {
    if (message.getDSR().isPresent) {
      return handleDSR(message.getDSR().value);
    }

    if (message.getType() == KernelResponseType.NodeMessage) {
      print("Message received, but no callback action yet");
    }

    if (message is ErrorKernelResponse) {
      print("Error: " + message.message);
    }
  }

  static void handleDSR(DomainSpecificResponse dsr) {
    switch (dsr.getType()) {
      case DomainSpecificResponseType.PostRegisterRequest:
        PostRegisterRequest req = dsr;
        Utils.pushNotification("Peer request from " + req.username, req.username + " would like to connect to " + req.implicatedCid.toString());
        return;

      default:
        print("Unaccounted DSR message type");
    }
  }

}

class DefaultHandler implements AbstractHandler {
  const DefaultHandler();

  @override
  CallbackStatus onTicketReceived(KernelResponse kernelResponse) {
    print("Default handler triggered: " + kernelResponse.getType().toString() + " [ticket: " + kernelResponse.getTicket().toString() + "]");
    return CallbackStatus.Complete;
  }

  @override
  void onErrorReceived(KernelResponse kernelResponse) {
    print("[ERR] Default handler triggered: " + kernelResponse.getMessage().value + " [ticket: " + kernelResponse.getTicket().toString() + "]");
  }

  @override
  void onConfirmation(KernelResponse kernelResponse) {
    print("Default handler triggered. Confirmation for " + kernelResponse.getTicket().toString());
  }

}