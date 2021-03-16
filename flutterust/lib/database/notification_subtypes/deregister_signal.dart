import 'package:flutter/material.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:flutterust/notifications/deregister_push_notification.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class DeregisterSignal extends AbstractNotification {
  final u64 recipientCid;
  final u64 peerCid;
  final DateTime recvTime;

  DeregisterSignal(this.recipientCid, this.peerCid, this.recvTime);
  DeregisterSignal.now(this.recipientCid, this.peerCid) : this.recvTime = DateTime.now();

  DeregisterSignal.fromMap(Map<String, dynamic> sqlMap, int id) :
      this.recipientCid = sqlMap["recipientCid"],
      this.peerCid = sqlMap["peerCid"],
      this.recvTime = DateTime.parse(sqlMap["recvTime"]),
        super.withId(id);

  @override
  Map<String, dynamic> toMap() {
    return {
      'recipientCid': this.recipientCid.toString(),
      'peerCid': this.peerCid.toString(),
      'recvTime': this.recvTime.toIso8601String()
    };
  }

  @override
  NotificationType get type => NotificationType.Deregister;

  @override
  DateTime get receiveTime => recvTime;

  @override
  IconData get notificationIcon => MdiIcons.accountOffOutline;

  @override
  Future<String> getNotificationTitle(ClientNetworkAccount implicatedCid) async {
    return await PeerNetworkAccount.getPeerByCid(this.recipientCid, this.peerCid).then((value) => value.value.peerUsername + " deregistered from ${implicatedCid.username}");
  }

  @override
  Future<void> onNotificationOpened(ClientNetworkAccount implicatedCid, BuildContext context) async {
    // we just delete this instance from the database
    await this.delete();
    if (Navigator.canPop(context)) {
      Navigator.pop(context);
    }
  }

  @override
  AbstractPushNotification toAbstractPushNotification() => DeregisterPushNotification.from(this);
}