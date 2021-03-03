import 'dart:collection';

import 'package:flutterust/database_handler.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/screens/session/home.dart';
import 'package:flutterust/screens/session/session_subscreens/post_register_invitation.dart';
import 'package:flutterust/utils.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/disconnect_response.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/kernel_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_request.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/root/kernel_shutdown.dart';
import 'package:satori_ffi_parser/types/root/message.dart';
import 'package:satori_ffi_parser/types/root/node_message.dart';
import 'package:satori_ffi_parser/types/ticket.dart';

class KernelResponseHandler {
  static final pendingTickets = HashMap<Ticket, KernelResponse>();

  /// When sending a command to the kernel, the kernel will immediately respond. This should be called
  /// `oneshot`: If oneshot is left as default, then once the ticket's callback is triggered, the callback will never again be called.
  /// If set to false, then an inbound ticket can indefinitely trigger the callback, so long as the callback continues to exist (useful for peer channels, groups, file-transfers, etc)
  static void handleFirstCommand(KernelResponse kernelResponse, { AbstractHandler handler = const DefaultHandler(), bool oneshot = true}) {
    kernelResponse.setCallbackAction(handler.onTicketReceived); // by DEFAULT, this runs when handleRustKernelMessage executes
    kernelResponse.setOneshot(oneshot);

    // TODO: Handle DSRs, as we get results on first command response
    switch (kernelResponse.getType()) {
      case KernelResponseType.ResponseTicket:
      case KernelResponseType.ResponseHybrid:
      case KernelResponseType.ResponseFcmTicket:
        switch (handler.onConfirmation(kernelResponse)) {
          case CallbackStatus.Pending:
            pendingTickets[kernelResponse.getTicket().value] = kernelResponse;
            break;

          default:
            print("onConfirmation implied completion of task. Will not store into hashmap");
        }

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
        handleUnexpectedSignal(message);
      }
    } else {
      // no ticket present; we don't interact with the message through callbacks. We need another way to handle these messages
      // if message type, send to session + notification
      handleUnexpectedSignal(message);
    }
  }

  static void handleUnexpectedSignal(KernelResponse message) async {
    if (message.getDSR().isPresent) {
      return handleUnexpectedDSR(message.getDSR().value);
    }

    switch (message.getType()) {
      case KernelResponseType.Message:
        MessageKernelResponse resp = message;
        print("Received kernel message: " + resp.message);
        break;

      case KernelResponseType.NodeMessage:
        NodeMessageKernelResponse resp = message;
        String username = (await ClientNetworkAccount.getUsernameByCid(resp.cid)).value;
        // TODO: route to chat screen/
        Utils.pushNotification("Message for " + username, resp.message);
        break;
        
      case KernelResponseType.Error:
        ErrorKernelResponse eRsp = message;
        print("ERR: " + eRsp.message);
        break;

      case KernelResponseType.KernelShutdown:
        KernelShutdown shutdown = message;
        print("The kernel has been shut down. Reason: ${shutdown.message}");
        RustSubsystem.init(force: true);
    }
  }

  static void handleUnexpectedDSR(DomainSpecificResponse dsr) async {
    switch (dsr.getType()) {
      case DomainSpecificResponseType.PostRegisterRequest:
        PostRegisterRequest req = dsr;
        String username = (await ClientNetworkAccount.getUsernameByCid(req.implicatedCid)).value;
        Utils.pushNotification("Peer request from " + req.username, req.username + " would like to connect to " + username, route: PostRegisterInvitation.routeName, arguments: req);
        return;

      case DomainSpecificResponseType.Disconnect:
        (HomePage.screens[SessionHomeScreen.IDX] as SessionHomeScreen).sendPort.send(dsr);
        break;

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
  CallbackStatus onConfirmation(KernelResponse kernelResponse) {
    print("Default handler triggered. Confirmation for " + kernelResponse.getTicket().toString());
    return CallbackStatus.Pending;
  }

}