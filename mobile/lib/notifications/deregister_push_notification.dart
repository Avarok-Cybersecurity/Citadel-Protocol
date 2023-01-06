import 'package:flutter/material.dart';
import 'package:flutterust/database/notification_subtypes/deregister_signal.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class DeregisterPushNotification extends AbstractPushNotification {
  final u64 recipientCid;
  final u64 peerCid;
  final DateTime recvTime;

  DeregisterPushNotification(this.recipientCid, this.peerCid, this.recvTime);
  DeregisterPushNotification.from(DeregisterSignal not): this(not.recipientCid, not.peerCid, not.recvTime);

  @override
  Future<Optional<Widget>> constructWidget() async {
    return Optional.empty();
  }

  @override
  PushNotificationType getType() => PushNotificationType.Deregister;

  @override
  Map<String, String> toPartialPreservableMap() {
    return {
      'recipientCid': this.recipientCid.toString(),
      'peerCid': this.peerCid.toString(),
      'recvTime': this.recvTime.toIso8601String()
    };
  }

  static AbstractPushNotification fromMap(Map<String, String> preservedMap) {
    return DeregisterPushNotification(u64.tryFrom(preservedMap["recipientCid"]).value, u64.tryFrom(preservedMap["peerCid"]).value, DateTime.parse(preservedMap["recvTime"]!));
  }

}