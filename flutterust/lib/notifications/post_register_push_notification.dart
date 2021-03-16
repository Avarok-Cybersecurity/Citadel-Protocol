import 'package:flutter/material.dart';
import 'package:flutterust/database/notification_subtypes/post_register.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/screens/session/session_subscreens/post_register_invitation.dart';
import 'package:optional/optional_internal.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class PostRegisterPushNotification extends AbstractPushNotification {
  final u64 implicatedCid;
  final u64 peerCid;
  final String peerUsername;
  final u64 mid;
  final bool isFcm;
  final DateTime recvTime;

  PostRegisterPushNotification(this.implicatedCid, this.peerCid, this.peerUsername, this.mid, this.isFcm, this.recvTime);
  PostRegisterPushNotification.from(PostRegisterNotification not) : this(not.implicatedCid, not.peerCid, not.peerUsername, not.mid, not.isFcm, not.recvTime);

  @override
  Future<Optional<Widget>> constructWidget() async {
    return Optional.of(PostRegisterInvitation(PostRegisterNotification(this.implicatedCid, this.peerCid, this.peerUsername, this.mid, this.isFcm, this.recvTime)));
  }

  @override
  PushNotificationType getType() => PushNotificationType.PostRegisterInvitation;

  @override
  Map<String, String> toPartialPreservableMap() {
    return {
      'implicatedCid': this.implicatedCid.toString(),
      'peerCid': this.peerCid.toString(),
      'peerUsername': this.peerUsername,
      'mid': this.mid.toString(),
      'isFcm': this.isFcm.toString(),
      'recvTime': this.recvTime.toIso8601String()
    };
  }

  static AbstractPushNotification fromMap(Map<String, String> preservedMap) {
    return PostRegisterPushNotification(
      u64.tryFrom(preservedMap["implicatedCid"]).value,
      u64.tryFrom(preservedMap["peerCid"]).value,
      preservedMap["peerUsername"],
      u64.tryFrom(preservedMap["mid"]).value,
      preservedMap["isFcm"] == "true",
      DateTime.parse(preservedMap["recvTime"])
    );
  }

}