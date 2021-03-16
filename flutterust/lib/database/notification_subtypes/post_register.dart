import 'package:flutter/material.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/notifications/post_register_push_notification.dart';
import 'package:flutterust/screens/session/session_subscreens/post_register_invitation.dart';
import 'package:flutterust/utils.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:satori_ffi_parser/types/dsr/post_register_request.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class PostRegisterNotification extends AbstractNotification {
  final u64 implicatedCid;
  final u64 peerCid;
  final String peerUsername;
  final u64 mid;
  final bool isFcm;
  final DateTime recvTime;

  PostRegisterNotification(this.implicatedCid, this.peerCid, this.peerUsername, this.mid, this.isFcm, this.recvTime);

  PostRegisterNotification.from(PostRegisterRequest req) : this(req.implicatedCid, req.peerCid, req.username, req.mid, req.isFcmType, DateTime.now());

  PostRegisterNotification.fromMap(Map<String, dynamic> sql, int id) :
      this.implicatedCid = u64.tryFrom(sql["implicatedCid"]).value,
  this.peerCid = u64.tryFrom(sql["peerCid"]).value,
  this.peerUsername = sql["peerUsername"],
  this.mid = u64.tryFrom(sql["mid"]).value,
  this.isFcm = sql["isFcm"],
  this.recvTime = DateTime.parse(sql["recvTime"]),
        super.withId(id);

  @override
  u64 get recipientCid => this.implicatedCid;

  @override
  Map<String, dynamic> toMap() {
    return {
      'implicatedCid': this.implicatedCid.toString(),
      'peerCid': this.peerCid.toString(),
      'peerUsername': this.peerUsername,
      'mid': this.mid.toString(),
      'isFcm': this.isFcm,
      'recvTime': this.recvTime.toIso8601String()
    };
  }

  @override
  NotificationType get type => NotificationType.PostRegisterRequest;

  @override
  DateTime get receiveTime => this.recvTime;

  @override
  IconData get notificationIcon => MdiIcons.accountPlusOutline;

  @override
  Future<String> getNotificationTitle(ClientNetworkAccount implicatedCid) {
    return Future.value("Register request from ${this.peerUsername}");
  }

  @override
  Future<void> onNotificationOpened(ClientNetworkAccount implicatedCid, BuildContext context) async {
    Navigator.push(context, Utils.createDefaultRoute(PostRegisterInvitation(this)));
  }

  @override
  AbstractPushNotification toAbstractPushNotification() => PostRegisterPushNotification.from(this);
}