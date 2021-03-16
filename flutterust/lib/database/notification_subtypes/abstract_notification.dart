import 'dart:convert';

import 'package:flutter/widgets.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/database_handler.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/notifications/abstract_push_notification.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/u64.dart';

abstract class AbstractNotification {

  // When a notification is loaded from the database, this constructor should be called to initialize
  // the instance to map to the corresponding entry in the database
  @mustCallSuper
  AbstractNotification.withId(int id) : this._dbKey = Optional.of(id);
  AbstractNotification();

  Map<String, dynamic> toMap();
  u64 get recipientCid;

  Future<String> getNotificationTitle(ClientNetworkAccount implicatedCid);
  Future<void> onNotificationOpened(ClientNetworkAccount implicatedCid, BuildContext context);

  AbstractPushNotification toAbstractPushNotification();

  DateTime get receiveTime;
  IconData get notificationIcon;

  // This value does not get loaded until sync() is called
  Optional<int> _dbKey = Optional.empty();

  NotificationType get type;

  String toRawJson() {
    return json.encode(this.toMap());
  }

  RawNotification toRawNotification() {
    return RawNotification.builder(this.recipientCid, this.type, this.toRawJson());
  }

  /// Saves to the database, returning the key ID.
  /// Note: This should always be run when constructing a notification for it to be later accessible
  Future<int> sync() async {
    this._dbKey = Optional.of(await this.toRawNotification().sync());
    return this._dbKey.value;
  }

  /// Returns true if a success
  Future<bool> delete() async {
    return await this._dbKey.map((key) => DatabaseHandler.removeObjectById(RawNotification.DB_TABLE, key)).orElse(Future.value(false));
  }
}