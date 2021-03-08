import 'package:flutter/material.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class MessageNotification extends AbstractNotification {
  final u64 recipient;
  final u64 sender;
  final String message;
  final DateTime recvTime;

  MessageNotification(this.recipient, this.sender, this.message, this.recvTime);
  /// This should be called when receiving a message
  MessageNotification.receivedNow(this.recipient, this.sender, this.message): this.recvTime = DateTime.now();
  /// This should be called when sending a message to keep tally in the DB for the chat screens
  /// Note the order here; it's in reverse compared to Self::receivedNow
  MessageNotification.sentNow(this.sender, this.recipient, this.message) : this.recvTime = DateTime.now();

  MessageNotification.fromMap(Map<String, dynamic> sqlMap, int id) :
        this.recipient = u64.tryFrom(sqlMap["recipient"]).value,
  this.sender = u64.tryFrom(sqlMap["sender"]).value,
  this.message = sqlMap["message"],
  this.recvTime = DateTime.parse(sqlMap["recvTime"]),
        super.withId(id);

  @override
  Map<String, dynamic> toMap() {
    return {
      'recipient': this.recipient.toString(),
      'sender': this.sender.toString(),
      'message': this.message,
      'recvTime': this.recvTime.toIso8601String()
    };
  }

  // Returns an row-ordered set of messages between two cids
  // TODO: consider optimizing this b/c this requires loading ALL messages
  static Future<List<MessageNotification>> loadMessagesBetween(u64 implicatedCid, u64 peerCid) async {
    // First, load all notifications for this cid
    return await RawNotification.loadNotificationsFor(implicatedCid).then((value) => value.whereType<MessageNotification>().where((element) => (element.sender == implicatedCid && element.recipient == peerCid) || (element.sender == peerCid && element.recipient == implicatedCid)).toList());
  }

  @override
  u64 get recipientCid => this.recipient;

  @override
  NotificationType get type => NotificationType.Message;

  @override
  DateTime get receiveTime => this.recvTime;

  @override
  IconData get notificationIcon => Icons.mail_outline;

  @override
  Future<String> getNotificationTitle(ClientNetworkAccount implicatedCid) async {
    return await PeerNetworkAccount.getPeerByCid(this.sender).then((value) => "Message from " +  value.map((pnac) => pnac.peerUsername).orElse("Server"));
  }

  @override
  Future<void> onNotificationOpened(ClientNetworkAccount implicatedCid, BuildContext context) async {
    print("TODO: pop-in message screen");
  }
}