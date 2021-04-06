
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/abstract_handler.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:flutterust/main.dart';
import 'package:satori_ffi_parser/types/u64.dart';

/// The purpose of this class is to ensure that all outbound messages get delivered. Previously, we would send through the protocol and forget. When that approach was used,
/// most of the time messages were delivered. HOWEVER, sometimes, especially when the recipient is in the background for an extended period of time, the message would not get
/// delivered. As such, what this class needs to ensure is that an outbound message won't get sent unless the previous message was DELIVERED. Once the previous message was delivered,
/// then the next message in the queue can be sent.
///
/// [0] This class gets passed a Message instance with a presumably null raw_ticket.
/// [1] Before sending, makes sure that the previous message has already been RECEIVED (SELECT * FROM messages WHERE implicatedCid = ? AND WHERE fromPeer = 0 ORDER BY id DESC LIMIT 1)
/// [1.5a] if previous message was received, just send it immediately
/// [1.5b] else, check lastEventTime (which is really sendTime in this case) to see if 15 minutes have passed
/// [1.5b-a] if 15 minutes have not passed, relax
/// [1.5b-b] else, send message again and wait
///
/// NOTE: the background poller should call the poll function periodically
/// NOTE: The onMessageReceived trigger should be called once a message is received
class MessageSendHandler {

  /// The response handler is not guaranteed to be called
  static Future<void> sendMessageFromScreen(Message message, PeerSendHandler handler) async {
    if (await _pollLastMessage(message.implicatedCid, message.peerCid)) {
      // We can send it
      await _dispatchMessage(message, handler);
    } else {
      // store ... since message exists, then it should be implies to exist. nothing to do here. It will automatically gets polled
    }
  }

  /// This should be called whenever a new message is received
  static Future<void> poll() async {
    var clients = await ClientNetworkAccount.getAllClients().then((value) => value.orElse([]));
    print("[MessageSendHandler] POLL: ${clients.length} clients");
    for (u64 implicatedCid in clients) {
      var peers = await PeerNetworkAccount.listAllForImplicatedCid(implicatedCid).then((value) => value.map((e) => e.peerCid).toList());
      print("[MessageSendHandler] POLL: ${peers.length} peers for $implicatedCid");
      for (u64 peerCid in peers) {
        // if false, will be sent automatically. If true, we don't do anything here specifically b/c we are merely polling
        await _pollLastMessage(implicatedCid, peerCid);
      }
    }
  }

  /// Returns true if the latest message was received (or, if no message existed), false otherwise. IF false, maybe internally resends the message (timer-permitting)
  static Future<bool> _pollLastMessage(u64 implicatedCid, u64 peerCid) async {
    var lastMessageOpt = await Message.getLastMessageSentBy(implicatedCid, peerCid);
    if (lastMessageOpt.isPresent) {
      var lastMessage = lastMessageOpt.value;

      switch (lastMessage.status) {
        case PeerSendState.MessageReceived:
          print("[MessageSendHandler] Message received! Will now allow next message between $implicatedCid and $peerCid");
          return true;

        default:
          print("[MessageSendHandler] We cannot send a message at this time");
          await _checkIfNeedsResend(lastMessage);
          return false;
      }
    } else {
      print("No last message between $implicatedCid and $peerCid");
      return true;
    }
  }

  static Future<void> _checkIfNeedsResend(Message lastMessage) async {
    if (DateTime.now().difference(lastMessage.lastEventTime) >= Duration(minutes: 15)) {
      // attempt resend
      lastMessage.lastEventTime = DateTime.now();
      await lastMessage.sync();
      await _dispatchMessage(lastMessage, PeerSendHandler.screenless(lastMessage));
    }
  }

  /// Sends a message unconditionally
  static Future<void> _dispatchMessage(Message message, AbstractHandler handler) async {
    var command = constructSendCommand(message);
    await RustSubsystem.bridge!.executeCommand(command)
        .then((value) => value.ifPresent((kResp) =>
        KernelResponseHandler.handleFirstCommand(kResp,
            handler: handler,
            oneshot: false)));
  }

  static String constructSendCommand(Message message) {
    return message.peerCid == u64.zero
        ? "switch ${message.implicatedCid} send ${message.message}"
        : "switch ${message.implicatedCid} peer send ${message.peerCid} --fcm ${message.message}";
  }
}