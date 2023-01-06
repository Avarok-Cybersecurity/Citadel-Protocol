import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutterust/components/default_widget.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/utils.dart';
import 'package:intl/intl.dart';

class NotificationsScreen extends StatefulWidget {
  final List<AbstractNotification> notifications;
  final ClientNetworkAccount cnac;
  final void Function(int) removeFromParent;

  NotificationsScreen(this.cnac, this.notifications, this.removeFromParent, { Key? key }) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return NotificationsScreenInner();
  }
}

class NotificationsScreenInner extends State<NotificationsScreen> {

  late final StreamSubscription<Message> messages;

  NotificationsScreenInner() {
    this.messages = Utils.broadcaster.stream.stream.listen((message) {
      // we don't need to add to the list since the notifications item is a pointer
      // to the parent who owns its object. We just need to refresh the view
      setState(() {});
    });
  }

  @override
  void initState() {
    super.initState();
  }

  @override
  void dispose() {
    super.dispose();
    this.messages.cancel();
  }

  @override
  Widget build(BuildContext context) {
    return DefaultPageWidget(
      align: Alignment.topCenter,
        title: Text("Notifications for ${this.widget.cnac.username}"),
        // prev: had SingleChildScrollWidget
        child: this.widget.notifications.isEmpty ? Text("No notifications!") : compileWidget(context),
      actions: [
        PopupMenuButton<String>(
          onSelected: onSettingsPressed,
          itemBuilder: (BuildContext context) {
            return {"Clear"}.map((String choice) {
              return PopupMenuItem<String>(
                value: choice,
                child: Text(choice),
              );
            }).toList();
          },
        )
      ],
    );
  }

  void onSettingsPressed(String selection) async {
    switch (selection.toLowerCase()) {
      case "clear":
        this.widget.notifications.clear();
        await RawNotification.deleteAllNotifications(this.widget.cnac.implicatedCid);
        setState(() {});
        break;
    }
  }

  FutureBuilder<ListView> compileWidget(BuildContext context) {
    return FutureBuilder(
      future: compileNotifications(context),
      builder: (context, snapshot) {
        if (snapshot.hasData) {
          return snapshot.data as ListView;
        } else {
          return Container(
            child: Center(
                child: CircularProgressIndicator()
            ),
          );
        }
      },
    );
  }

  Future<ListView> compileNotifications(BuildContext context) async {
    return ListView(
      key: UniqueKey(),
      shrinkWrap: true,
      // we want the most recent notification on top, and as such, must add the entries in reverse
      children: await Stream.fromIterable(this.widget.notifications.asMap().entries.toList().reversed).asyncMap((e) async {
      return Card(
          child: InkWell(
            child: Dismissible(
              key: Key(e.value.hashCode.toString()),
              background: Container(color: Colors.red),
              onDismissed: (direction) {
                onNotificationTapped(e.value, e.key, context, dismissOnly: true);

                ScaffoldMessenger
                    .of(context).removeCurrentSnackBar();
                ScaffoldMessenger
                    .of(context).showSnackBar(SnackBar(duration: Duration(seconds: 1), key: UniqueKey(), content: Text("Notification dismissed")));
              },
              child: ListTile(
                onTap: () => onNotificationTapped(e.value, e.key, context),
                leading: Icon(e.value.notificationIcon, size: 56.0),
                title: Text(
                  await e.value.getNotificationTitle(this.widget.cnac),
                  style: TextStyle(
                      fontWeight: FontWeight.bold
                  ),
                ),
                subtitle: Text("Received ${getDisplayTime(e.value.receiveTime)}"),
                trailing: Icon(Icons.arrow_right),
              ),
            )
          ));
    }).toList()
    );
  }

  void onNotificationTapped(AbstractNotification notification, int idx, BuildContext context, {bool dismissOnly = false}) async {
    print("Tap pressed on ${notification.type}, idx in parent = $idx");
    if (!dismissOnly) {
      await notification.onNotificationOpened(this.widget.cnac, context);
    } else {
      await notification.delete();
    }

    this.widget.removeFromParent(idx);

    setState(() {});
  }

  String getDisplayTime(DateTime time) {
    DateTime now = DateTime.now();
    DateTime today = DateTime(now.year, now.month, now.day);
    DateTime yesterday = DateTime(now.year, now.month, now.day - 1);
    DateTime dayRecv = DateTime(time.year, time.month, time.day);

    if (dayRecv == today) {
      return "Today ${DateFormat.jm().format(time)}";
    } else if (dayRecv == yesterday) {
      return "Yesterday ${DateFormat.jm().format(time)}}";
    } else {
      return DateFormat.MMMMd().format(time) + " " + DateFormat.jm().format(time);
    }
  }
}
