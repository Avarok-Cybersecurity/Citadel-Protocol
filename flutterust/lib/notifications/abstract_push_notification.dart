import 'package:flutter/material.dart';
import 'package:flutterust/notifications/message_push_notification.dart';
import 'package:flutterust/notifications/post_register_push_notification.dart';
import 'package:optional/optional.dart';

abstract class AbstractPushNotification {
  // This should not be called from the outside, only inherited class members
  Map<String, String> toPartialPreservableMap();
  PushNotificationType getType();
  Future<Optional<Widget>> constructWidget();

  /// The outside should call this
  Map<String, String> getPreservableMap() {
    var map = this.toPartialPreservableMap();
    map["type"] = this.getType().toString().split(".").last;
    return map;
  }

  static Optional<AbstractPushNotification> tryFromMap(Map<String, String> preservedMap) {
    try {
      PushNotificationType id = PushNotificationTypeExt.fromString(preservedMap["type"]).value;

      switch (id) {
        case PushNotificationType.Message:
          return Optional.of(MessagePushNotification.fromMap(preservedMap));

        case PushNotificationType.PostRegisterInvitation:
          return Optional.of(PostRegisterPushNotification.fromMap(preservedMap));

        case PushNotificationType.Deregister:
          return Optional.of(PostRegisterPushNotification.fromMap(preservedMap));
      }
    } catch(_) {}

    return Optional.empty();
  }
}

enum PushNotificationType {
  Message,
  PostRegisterInvitation,
  Deregister
}

extension PushNotificationTypeExt on PushNotificationType {
  static Optional<PushNotificationType> fromString(String type) {
    try {
      return Optional.of(PushNotificationType.values.firstWhere((element) => element.toString().split('.').last == type));
    } catch(_) {
      return Optional.empty();
    }
  }
}