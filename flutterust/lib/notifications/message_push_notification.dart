import 'package:flutter/material.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/database_handler.dart';
import 'package:flutterust/database/notification_subtypes/notification_message.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/screens/session/session_subscreens/messaging_screen.dart';
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class MessagePushNotification extends AbstractPushNotification {
  final u64 implicatedCid;
  final u64 peerCid;
  final Optional<int> dbKey;

  MessagePushNotification(this.implicatedCid, this.peerCid, this.dbKey);

  MessagePushNotification.from(MessageNotification not) : this.implicatedCid = not.recipientIsLocal ? not.recipient : not.sender,
  this.peerCid = not.recipientIsLocal ? not.sender : not.recipient,
  this.dbKey = not.getDbKey();


  @override
  Future<Optional<Widget>> constructWidget() async {
    var cnacOpt = await ClientNetworkAccount.getCnacByCid(this.implicatedCid);
    var peerNacOpt = await PeerNetworkAccount.getPeerByCid(this.implicatedCid, this.peerCid);

    if (cnacOpt.isPresent && peerNacOpt.isPresent) {
      return Optional.of(MessagingScreen(cnacOpt.value, peerNacOpt.value));
    }

    return Optional.empty();
  }

  @override
  PushNotificationType getType() => PushNotificationType.Message;

  @override
  Map<String, String> toPartialPreservableMap() {
    return {
      'implicatedCid' : this.implicatedCid.toString(),
      'peerCid' : this.peerCid.toString(),
      'dbKey': this.dbKey.orElse(-1).toString()
    };
  }

  static AbstractPushNotification fromMap(Map<String, String> preservedMap) {
    int dbKey = int.parse(preservedMap["dbKey"]);
    return MessagePushNotification(u64.tryFrom(preservedMap["implicatedCid"]).value, u64.tryFrom(preservedMap["peerCid"]).value, dbKey != -1 ? Optional.of(dbKey) : Optional.empty());
  }

  Future<bool> maybeDelete() async {
    return await this.dbKey.map((key) => MessageNotification.fromRawIdDirty(key).delete()).orElse(Future.value(false));
  }
}