import 'dart:collection';

import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/notification_subtypes/deregister_signal.dart';
import 'package:flutterust/database/notification_subtypes/notification_message.dart';
import 'package:flutterust/database/notification_subtypes/post_register.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/auto_login.dart';
import 'package:flutterust/misc/message_send_handler.dart';
import 'package:flutterust/utils.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/parser.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/deregister_response.dart';
import 'package:satori_ffi_parser/types/dsr/disconnect_response.dart';
import 'package:satori_ffi_parser/types/dsr/fcm/fcm_message.dart';
import 'package:satori_ffi_parser/types/dsr/fcm/fcm_message_received.dart';
import 'package:satori_ffi_parser/types/kernel_response.dart';
import 'package:satori_ffi_parser/types/kernel_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_request.dart';
import 'package:satori_ffi_parser/types/root/error.dart';
import 'package:satori_ffi_parser/types/root/kernel_initiated.dart';
import 'package:satori_ffi_parser/types/root/kernel_shutdown.dart';
import 'package:satori_ffi_parser/types/root/message.dart';
import 'package:satori_ffi_parser/types/root/node_message.dart';
import 'package:satori_ffi_parser/types/ticket.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class KernelResponseHandler {
  static final pendingTickets = HashMap<Ticket, KernelResponse>();

  /// When sending a command to the kernel, the kernel will immediately respond. This should be called
  /// `oneshot`: If oneshot is left as default, then once the ticket's callback is triggered, the callback will never again be called.
  /// If set to false, then an inbound ticket can indefinitely trigger the callback, so long as the callback continues to exist (useful for peer channels, groups, file-transfers, etc)
  static void handleFirstCommand(KernelResponse kernelResponse, { AbstractHandler handler = const DefaultHandler(), bool oneshot = true}) {
    print("Handing first command for kResp w/ticket ${kernelResponse.getTicket()}");
    kernelResponse.setCallbackAction(handler.onTicketReceived); // by DEFAULT, this runs when handleRustKernelMessage executes
    kernelResponse.setOneshot(oneshot);

    switch (kernelResponse.getType()) {
      case KernelResponseType.Error:
        handler.onErrorReceived(kernelResponse as ErrorKernelResponse);
        return;

      default:
        break;
    }

    if (kernelResponse.getTicket().isPresent) {
      switch (handler.onConfirmation(kernelResponse)) {
        case CallbackStatus.Pending:
          if (pendingTickets.containsKey(kernelResponse.getTicket().value)) {
            print("***WARNING*** PendingTickets already has a pre-existing entry. If this is a local debug test, this is expected when communicating between two clients on the same phone. Else, error");
            return;
          }

          pendingTickets[kernelResponse.getTicket().value] = kernelResponse;
          break;

        default:
          print("onConfirmation implied completion of task. Will not store into hashmap");
      }
    }
  }

  // FFI packets get sent here when the rust kernel sends messages
  static void handleRustKernelRawMessage(String ffiPacket) {
    FFIParser.tryFrom(ffiPacket)
        .ifPresent(handleRustKernelMessage, orElse: () {
          print("***ERROR*** Unable to decode FFI Packet: " + ffiPacket);
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
          switch (await callback.value(message)) {
            case CallbackStatus.Complete:
              print("Callback signalled completion. Removing from pending tickets ...");
              pendingTickets.remove(message.getTicket().value);
              break;

            case CallbackStatus.Unexpected:
              handleUnexpectedSignal(message);
              break;

            default:
              // if pending, then this can be triggered again
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
        MessageKernelResponse resp = message as MessageKernelResponse;
        print("Received kernel message: " + resp.message);
        break;

      case KernelResponseType.NodeMessage:
        NodeMessageKernelResponse resp = message as NodeMessageKernelResponse;
        await _handleMessage(resp.cid, resp.peerCid, resp.message, resp.ticket.id);
        break;
        
      case KernelResponseType.Error:
        ErrorKernelResponse eRsp = message as ErrorKernelResponse;
        print("ERR: " + eRsp.message);
        break;

      case KernelResponseType.KernelShutdown:
        KernelShutdown shutdown = message as KernelShutdown;
        print("The kernel has been shut down. Reason: ${shutdown.message}");
        RustSubsystem.init(force: true);
        break;

      case KernelResponseType.KernelInitiated:
        print("Received signal that the kernel has been initiated. Sending signal to allow continuation of other subroutines. ...");
        Utils.kernelInitiatedSink.sink.add(message as KernelInitiated);
        break;

      default:
        break;
    }
  }

  static void handleUnexpectedDSR(DomainSpecificResponse dsr) async {
    switch (dsr.getType()) {
      case DomainSpecificResponseType.PostRegisterRequest:
        PostRegisterRequest req = dsr as PostRegisterRequest;

        String username = (await ClientNetworkAccount.getUsernameByCid(req.implicatedCid)).value;
        PostRegisterNotification notification = PostRegisterNotification.from(req);
        int id = await notification.sync();
        print("Message DB-id: $id");

        if (HomePage.screens != null) {
          HomePage.pushObjectToSession(notification);
        }

        Utils.pushNotification("Peer request from " + req.username, req.username + " would like to connect to " + username, apn: notification.toAbstractPushNotification());
        return;

      case DomainSpecificResponseType.Disconnect:
        HomePage.pushObjectToSession(dsr);
        AutoLogin.onDisconnectSignalReceived(dsr as DisconnectResponse);
        break;

      case DomainSpecificResponseType.DeregisterResponse:
        DeregisterResponse resp = dsr as DeregisterResponse;
        if (resp.success) {
          DeregisterSignal notification = DeregisterSignal.now(resp.implicatedCid, resp.peerCid);
          int id = await notification.sync();
          print("[Deregister] notification ID: $id");
          if (HomePage.screens != null) {
            HomePage.pushObjectToSession(notification);
          }
          
          String username = await PeerNetworkAccount.getPeerByCid(resp.implicatedCid, resp.peerCid).then((value) => value.value.peerUsername);
          String localUsername = await ClientNetworkAccount.getUsernameByCid(resp.implicatedCid).then((value) => value.value);

          Utils.pushNotification("Deregistration", "$username no longer registered to $localUsername", apn: notification.toAbstractPushNotification());
        } else {
          print("**ERROR: Unaccounted Deregister signal that failed");
        }

        break;

      case DomainSpecificResponseType.FcmMessage:
        FcmMessage message = dsr as FcmMessage;
        // When message A gets sent but isn't received for awhile, a clone of A called B is sent. Suppose A is received before B. The PeerSentHandler of A completes,
        // meaning that once B arrives, we come here. Check to make sure the message hasn't already arrived before handling it like normal
        if (await Message.getMessage(message.ticket.targetCid, message.ticket.sourceCid, message.ticket.ticket, localRecvOnly: true).then((value) => value.isEmpty)) {
          await _handleMessage(message.ticket.targetCid, message.ticket.sourceCid, message.message, message.ticket.ticket);
        } else {
          print("DUPLICATE packet ${message.ticket} received; dropping");
        }

        break;

      case DomainSpecificResponseType.FcmMessageReceived:
        // A message's ACK may return when in the background (this is pretty likely). We need to access the message's notification and update it,
        // thus allowing the user to see the "received" sign once the message is back up.
        FcmMessageReceived message = dsr as FcmMessageReceived;
        // note: the below value may be null if order is not enforced (should be fixed now)
        Message msg = await Message.getMessage(message.ticket.sourceCid, message.ticket.targetCid, message.ticket.ticket).then((value) => value.value);
        msg.status = PeerSendState.MessageReceived;
        await msg.sync();
        print("Updated message state for $msg");
        // Now, call poll for this DSR
        await MessageSendHandler.poll();
        break;
      default:
        print("Unaccounted DSR message type");
    }
  }

  static Future<void> _handleMessage(u64 implicatedCid, u64 peerCid, String message, u64 rawTicket) async {
    ClientNetworkAccount implicatedCnac = await ClientNetworkAccount.getCnacByCid(implicatedCid).then((value) => value.value);
    String username = implicatedCnac.username;

    // TODO: incorporate FCM post-register ACKS to ensure the below doesn't return null
    //PeerNetworkAccount peerNac = await PeerNetworkAccount.getPeerByCid(implicatedCid, peerCid).then((value) => value.value);

    MessageNotification notification = MessageNotification.receivedNow(implicatedCid, peerCid, message, rawTicket);
    int id = await notification.sync();
    print("Message DB-id: $id");
    // push to the session screen, if possible.
    // if this is invoked in the background, the static memory may not be loaded. In this case,
    // since the notification is already in the database, once the session screen reloads, the
    // notifications will repopulate
    if (HomePage.screens != null) {
      HomePage.pushObjectToSession(notification);
      Utils.broadcaster.broadcast(notification.toMessage());
    }

    // if we are in the background, and the screen was never destroyed, we won't get a notification

    if (Utils.currentlyOpenedMessenger != Optional.of(implicatedCid)) {
      // only save the notification if not in the screen
      //var screen = MessagingScreen(implicatedCnac, peerNac);
      Utils.pushNotification("Message for $username ", message, apn: notification.toAbstractPushNotification());
    } else {
      print("Will not push message to notifications (already in messenger screen)");
    }
  }
}

class DefaultHandler implements AbstractHandler {
  const DefaultHandler();

  @override
  Future<CallbackStatus> onTicketReceived(KernelResponse kernelResponse) async {
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