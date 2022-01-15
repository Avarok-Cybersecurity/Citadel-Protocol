import 'package:flutter/material.dart';
import 'package:flutter_easyloading/flutter_easyloading.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/peer_sent_handler.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/notifications/message_push_notification.dart';
import 'package:flutterust/screens/session/session_subscreens/messaging_screen.dart';
import 'package:flutterust/utils.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class MessageNotification extends AbstractNotification {
  final u64? recipient;
  final u64? sender;
  final String? message;
  final DateTime? recvTime;
  final bool? recipientIsLocal;
  final PeerSendState? status;
  final u64? rawTicket;

  MessageNotification(this.recipient, this.sender, this.message, this.recvTime, this.recipientIsLocal, this.status, this.rawTicket);
  /// This should be called when receiving a message
  MessageNotification.receivedNow(this.recipient, this.sender, this.message, this.rawTicket): this.recvTime = DateTime.now(), this.recipientIsLocal = true, this.status = PeerSendState.MessageReceived;

  MessageNotification.fromMap(Map<String, dynamic> sqlMap, int id) :
        this.recipient = u64.tryFrom(sqlMap["recipient"]).value,
  this.sender = u64.tryFrom(sqlMap["sender"]).value,
  this.message = sqlMap["message"],
  this.recvTime = DateTime.parse(sqlMap["recvTime"]),
  this.recipientIsLocal = sqlMap["recipientIsLocal"],
  this.status = PeerSendStateExt.fromString(sqlMap["status"]).value,
  this.rawTicket = u64.tryFrom(sqlMap["rawTicket"]).value,
        super.withId(id);

  /// This should only be called when expecting to immediately call delete or some function that does not depend on the internal valued other than the id
  MessageNotification.fromRawIdDirty(int dbKey, {this.recipient, this.sender, this.message, this.recvTime, this.recipientIsLocal, this.status, this.rawTicket}): super.withId(dbKey);

  @override
  Map<String, dynamic> toMap() {
    return {
      'recipient': this.recipient.toString(),
      'sender': this.sender.toString(),
      'message': this.message,
      'recvTime': this.recvTime!.toIso8601String(),
      'recipientIsLocal': this.recipientIsLocal,
      'status': this.status!.asString(),
      'rawTicket': this.rawTicket.toString()
    };
  }

  // Returns an row-ordered set of messages between two cids
  // TODO: consider optimizing this b/c this requires loading ALL messages. Try past 100 messages
  static Future<List<MessageNotification>> loadMessagesBetween(u64 implicatedCid, u64 peerCid) async {
    // First, load all notifications for this cid
    return await RawNotification.loadNotificationsFor(implicatedCid).then((value) => value.whereType<MessageNotification>().where((element) => (element.sender == implicatedCid && element.recipient == peerCid) || (element.sender == peerCid && element.recipient == implicatedCid)).toList());
  }

  /// Note: this returns none if the provided localImplicatedCid does not match one of the internally-stored clients
  Message toMessage() {
    if (this.recipientIsLocal!) {
      // implies peer sent it
      return Message(this.recipient!, this.sender!, this.message!, this.recvTime!, true, this.status!, this.rawTicket!);
    } else {
      // implies local sent it
      return Message(this.sender!, this.recipient!, this.message!, this.recvTime!, false, this.status!, this.rawTicket!);
    }
  }

  @override
  u64 get recipientCid => this.recipient!;

  @override
  NotificationType get type => NotificationType.Message;

  @override
  DateTime get receiveTime => this.recvTime!;

  @override
  IconData get notificationIcon => Icons.mail_outline;

  @override
  Future<String> getNotificationTitle(ClientNetworkAccount implicatedCid) async {
    u64 implicatedCid = this.recipientIsLocal! ? this.recipientCid : this.sender!;
    u64 peerCid = this.recipientIsLocal! ? this.sender! : this.recipientCid;

    return await PeerNetworkAccount.getPeerByCid(implicatedCid, peerCid).then((value) => "Message from " +  value.map((pnac) => pnac.peerUsername).value);
  }

  @override
  /// when we sync this type of message, we simultaneously want to save its message form inside the messages database to make it accessible by the messaging screen
  Future<int> sync() async {
    int val = await super.sync();
    await this.toMessage().sync();
    return val;
  }

  @override
  Future<void> onNotificationOpened(ClientNetworkAccount implicatedCnac, BuildContext context) async {
    print("Deleting message from notifications list ...");
    await this.delete();
    PeerNetworkAccount.getPeerByCid(implicatedCnac.implicatedCid, this.recipientIsLocal! ? this.sender! : this.recipientCid)
    .then((value) => value.map((peerNac) => Navigator.push(context, Utils.createDefaultRoute(MessagingScreen(implicatedCnac, peerNac)))).orElseGet(() => EasyLoading.showError("Peer not found locally", dismissOnTap: true)));
  }

  @override
  AbstractPushNotification toAbstractPushNotification() {
    return MessagePushNotification.from(this);
  }
}