import 'dart:isolate';

import 'package:flutter/material.dart';
import 'package:flutterust/components/default_widget.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';

class NotificationsScreen extends StatelessWidget {
  final List<AbstractNotification> notifications;
  final ClientNetworkAccount cnac;
  final void Function(int) removeFromParent;

  const NotificationsScreen(this.cnac, this.notifications, this.removeFromParent);

  @override
  Widget build(BuildContext context) {
    return DefaultPageWidget(
      align: Alignment.topCenter,
        title: Text("Notifications for ${this.cnac.username}"),
        child: this.notifications.isEmpty ? Text("No notifications!") : compileWidget(context)
    );
  }

  FutureBuilder<ListView> compileWidget(BuildContext context) {
    return FutureBuilder(
      future: compileNotifications(context),
      builder: (context, snapshot) {
        return snapshot.data;
      },
    );
  }

  Future<ListView> compileNotifications(BuildContext context) async {
    return ListView(
      shrinkWrap: true,
      // we want the most recent notification on top, and as such, must add the entries in reverse
      children: await Stream.fromIterable(this.notifications.asMap().entries.toList().reversed).asyncMap((e) async {
      return Card(
          child: InkWell(
            child: ListTile(
              onTap: () => onNotificationTapped(e.value, e.key, context),
              leading: Icon(e.value.notificationIcon, size: 56.0),
              title: Text(
                await e.value.getNotificationTitle(this.cnac),
                style: TextStyle(
                    fontWeight: FontWeight.bold
                ),
              ),
              subtitle: Text("Received ${getDisplayTime(e.value.receiveTime)}"),
              trailing: Icon(Icons.arrow_right),
            ),
          ));
    }).toList()
    );
  }

  void onNotificationTapped(AbstractNotification notification, int idx, BuildContext context) async {
    print("Tap pressed on ${notification.type}, idx in parent = $idx");
    await notification.onNotificationOpened(this.cnac, context);
    this.removeFromParent(idx);
  }

  String getDisplayTime(DateTime time) {
    DateTime now = DateTime.now();
    DateTime today = DateTime(now.year, now.month, now.day);
    DateTime yesterday = DateTime(now.year, now.month, now.day - 1);
    DateTime dayRecv = DateTime(time.year, time.month, time.day);

    if (dayRecv == today) {
      return "Today ${time.hour}:${time.minute}" + (time.hour < 12 ? "AM" : "PM");
    } else if (dayRecv == yesterday) {
      return "Yesterday ${time.hour}:${time.minute}" + (time.hour < 12 ? "AM" : "PM");
    } else {
      return "${time.year}-${time.month}-${time.day} @ ${time.hour}:${time.minute}" + (time.hour < 12 ? "AM" : "PM");
    }
  }
}
