// "CREATE TABLE ${Notification.DB_TABLE} (id INTEGER PRIMARY KEY AUTOINCREMENT, cid TEXT, type INTEGER, payload TEXT",
// This is an intermediary form before being reinterpreted as a more useful sort of notification
import 'dart:convert';

import 'package:flutterust/database/abstract_sql_object.dart';
import 'package:flutterust/database/database_handler.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notification_subtypes/deregister_signal.dart';
import 'package:flutterust/database/notification_subtypes/notification_message.dart';
import 'package:flutterust/database/notification_subtypes/post_register.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:sqflite/sql.dart';

// "CREATE TABLE ${RawNotification.DB_TABLE} (id INTEGER PRIMARY KEY AUTOINCREMENT, cid TEXT, type TEXT, payload TEXT",
class RawNotification extends AbstractSqlObject {
  static const String DB_TABLE = "notifications";
  static const String GENESIS = "CREATE TABLE $DB_TABLE (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, cid TEXT, type TEXT, payload TEXT)";

  int _id;
  final u64 cid;
  final NotificationType notificationType;
  final String payload;

  /// Expects the payload to already be a JSON-encoded map
  RawNotification.builder(this.cid, this.notificationType, this.payload);

  RawNotification.fromMap(Map<String, dynamic> sqlMap) :
  this._id = sqlMap["id"],
  this.cid = u64.tryFrom(sqlMap["cid"]).value,
  this.notificationType = NotificationTypeExt.fromString(sqlMap["type"]).value,
  this.payload = sqlMap["payload"];

  @override
  String getTableName() {
    return DB_TABLE;
  }

  @override
  Map<String, dynamic> toMap() {
    // we omit the ID when serializing since the database has an autoincrement on it
    return {
      'cid': this.cid.toString(),
      'type': this.notificationType.toString().split(".").last,
      'payload': this.payload
    };
  }

  Optional<AbstractNotification> toNotification() {
    try {
      assert (this._id != null);

      final int id = this._id;
      final Map<String, dynamic> jsonMap = json.decode(this.payload);
      switch (this.notificationType) {
        case NotificationType.Message:
          return MessageNotification.fromMap(jsonMap, id).toOptional;

        case NotificationType.Deregister:
          return DeregisterSignal.fromMap(jsonMap, id).toOptional;

        case NotificationType.PostRegisterRequest:
          return PostRegisterNotification.fromMap(jsonMap, id).toOptional;
      }
    } catch(e) {
      print("Unable to convert toNotification: $e");
    }

    return Optional.empty();
  }

  @override
  Future<int> sync({ConflictAlgorithm conflictAlgorithm}) async {
    this._id = await super.sync(conflictAlgorithm: conflictAlgorithm);
    return this._id;
  }

  static Future<List<AbstractNotification>> loadNotificationsFor(u64 cid) {
    return DatabaseHandler.getObjectsByFieldValue(RawNotification.DB_TABLE, "cid", cid.toString(), (rawMap) => RawNotification.fromMap(rawMap))
        .then((value) => value.map((rawNotifications) => rawNotifications.map((rawNotification) => rawNotification.toNotification().value).toList()).orElse([]));
  }

  @override
  Optional getDatabaseKey() {
    return Optional.ofNullable(this._id);
  }
}

enum NotificationType {
  Message,
  Deregister,
  PostRegisterRequest
}

extension NotificationTypeExt on NotificationType {

  static Optional<NotificationType> fromString(String type) {
    try {
      return Optional.of(NotificationType.values.firstWhere((element) => element.toString().split('.').last == type));
    } catch(_) {
      return Optional.empty();
    }
  }
}