
import 'dart:async';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/custom_tab_view.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/notification_subtypes/abstract_notification.dart';
import 'package:flutterust/database/notifications.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/auto_login.dart';
import 'package:flutterust/misc/secure_storage_handler.dart';
import 'package:flutterust/screens/session/session_subscreens/notifications_screen.dart';
import 'package:flutterust/screens/session/session_view.dart';
import 'package:flutterust/themes/default.dart';
import 'package:flutterust/utils.dart';
import 'package:optional/optional.dart';
import 'package:quiver/iterables.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/dsr/disconnect_response.dart';
import 'package:satori_ffi_parser/types/dsr/get_active_sessions.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:satori_ffi_parser/types/virtual_connection_type.dart';

class SessionHomeScreen extends StatefulWidget {
  static const String routeName = "/sessions";
  static const IDX = 2;

  final StreamController<dynamic> controller = StreamController();

  SessionHomeScreen({Key? key}) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return SessionHomeScreenInner();
  }
}

class SessionHomeScreenInner extends State<SessionHomeScreen> {
  List<String> tabs = [];
  List<SessionView> sessionViews = [];
  List<List<AbstractNotification>> notifications = [];

  late final StreamSubscription<dynamic> listener;
  int pos = 0;

  @override
  void initState() {
    super.initState();

    this.listener = this.widget.controller.stream.listen((message) async {
      if (message is AbstractNotification) {
        var cid = message.recipientCid;
        int idx = this.sessionViews.indexWhere((element) => element.cnac.implicatedCid == cid);
        if (idx != -1) {
          this.notifications[idx].add(message);
        }
      } else {
        await handle(message);
      }

      setState(() {});
    });

    this.onStart();
  }

  @override
  void dispose() {
    super.dispose();
    this.listener.cancel();
  }

  /// initState cannot be async, so the function is moved to a separate fn
  void onStart() async {
    (await RustSubsystem.bridge!.executeCommand("list-sessions"))
        .ifPresent((kResp) => kResp.getDSR().ifPresent((dsr) => this.widget.controller.sink.add(dsr)));
  }

  /// handles either Connect or Disconnect dsr types, or, message types
  Future<void> handle(DomainSpecificResponse dsr) async {
    print("[SessionHomeScreen] recv'd dsr " + dsr.getType().toString());
      switch (dsr.getType()) {
        case DomainSpecificResponseType.Connect:
          ConnectResponse conn = dsr as ConnectResponse;
          if (conn.success) {
            // first, check to see that the session isn't already added. Sometimes, an old session stays stored
            // in memory because of background mode preventing a signal from reaching here
            var idxPrev = this.sessionViews.indexWhere((element) => element.cnac.implicatedCid == conn.implicatedCid);
            if (idxPrev != -1) {
              print("Will omit adding session ${conn.implicatedCid} because it already exists");
              return;
            }

            print("Adding session to sessions list for " + conn.implicatedCid.toString());
            //final String username = conn.getAttachedUsername().orElse("UNATTACHED USERNAME");
            var cnac = (await ClientNetworkAccount.getCnacByCid(conn.implicatedCid)).value;
            var storedNotifications = await RawNotification.loadNotificationsFor(cnac.implicatedCid);
            print("[Notification-Loader] Loaded: ${storedNotifications.length} notifications");

            tabs.add(cnac.username);
            notifications.add(storedNotifications);
            sessionViews.add(SessionView(cnac, widget.key));

            // TODO: Merge multiple possible users into a single one per device
            if (conn.jwt.isPresent) {
              print("JWT present: ${conn.jwt.value}");
              var creds = await FirebaseAuth.instance.signInWithCustomToken(conn.jwt.value);
              print("Creds obtained: $creds");

              await Utils.configureRTDB(cnac.implicatedCid);
            }

            print("Len: " + tabs.length.toString() + ", len: " + sessionViews.length.toString());
          }

          break;

        case DomainSpecificResponseType.GetActiveSessions:
          GetSessionsResponse resp = dsr as GetSessionsResponse;
          if (resp.cids.length != 0) {
            List<List<Object>> vals = zip(([resp.cids, resp.usernames])).where((data) {
              u64 cid = data[0] as u64;
              return this.sessionViews.indexWhere((widget) => widget.cnac.implicatedCid == cid) == -1;
            }).toList(growable: false);

            print("Found " + vals.length.toString() + " sessions unaccounted for in the GUI");
            for (int i = 0; i < vals.length; i++) {
              tabs.add(vals[i][1] as String);
              var cnac = await ClientNetworkAccount.getCnacByCid(vals[i][0] as u64);
              notifications.add([]);
              sessionViews.add(SessionView(cnac.value, widget.key));
            }

            print("Len: " + tabs.length.toString() + ", len: " + sessionViews.length.toString());
          } else {
            this.sessionViews.clear();
            this.pos = 0;
          }
          break;

        case DomainSpecificResponseType.Disconnect:
          DisconnectResponse dc = dsr as DisconnectResponse;
          switch(dc.virtualConnectionType) {
            case VirtualConnectionType.HyperLANPeerToHyperLANServer:
              int idx = this.sessionViews.indexWhere((element) => element.cnac.implicatedCid == dc.implicatedCid);
              if (idx != -1) {
                print("Disconnect occurred. Will remove idx $idx");

                this.tabs.removeAt(idx);
                this.notifications.removeAt(idx);
                this.sessionViews.removeAt(idx);
              }
              break;

            default: break;
          }

          break;

        default: break;
      }
  }

  @override
  Widget build(BuildContext context) {
    if (this.tabs.isEmpty) {
      return Center(
        child: Text("No active sessions"),
      );
    } else {
      return Scaffold(
        body: SafeArea(
          child: CustomTabView(
            initPosition: this.tabs.length != 0 ? this.pos : 0,
            itemCount: this.tabs.length,
            tabBuilder: (context, index) => Tab(text: this.tabs[index]),
            pageBuilder: (context, index) => Center(child: this.sessionViews[index]),
            onPositionChange: (index) {
              print("Pos changing: " + index.toString());
              pos = index;
              setState(() {});
            },
          ),
        ),

        bottomNavigationBar: BottomNavigationBar(
          fixedColor: primaryColor(),
          onTap: (idx) async {
            if (this.sessionViews.length != 0) {
              if (idx == 0) {
                // handle notifications. Idea: route push
                var cnac = getClientOfCurrentView().value;
                List<AbstractNotification> notifications = await RawNotification.loadNotificationsFor(cnac.implicatedCid);
                this.notifications[pos] = notifications;
                print("Loaded ${notifications.length} notifications for ${cnac.username}");
                Navigator.push(context, Utils.createDefaultRoute(NotificationsScreen(cnac, notifications, (idx) {
                  try {
                    this.notifications[pos].removeAt(idx);
                    setState(() {});
                  } catch(_) {}
                })));
              } else if (idx == 1) {

              } else if (idx == 2) {
                print("Logging out!");
                disconnectCurrentSession();
              }

              setState(() {});
            }
          },

          items: [
            getNotificationItem(),

            const BottomNavigationBarItem(
                icon: Icon(Icons.settings, color: Colors.black26),
                label: "Settings"
            ),

            const BottomNavigationBarItem(
                icon: Icon(Icons.logout, color: Colors.black26),
                label: "Logout"
            )
          ]
        ),
      );
    }
  }

  BottomNavigationBarItem getNotificationItem() {
    return BottomNavigationBarItem(
      icon: new Stack(
        children: <Widget>[
          new Icon(Icons.notifications, color: Colors.black26),
          new Positioned(
            right: 0,
            child: new Container(
              padding: EdgeInsets.all(1),
              decoration: new BoxDecoration(
                color: Colors.red,
                borderRadius: BorderRadius.circular(6),
              ),
              constraints: BoxConstraints(
                minWidth: 12,
                minHeight: 12,
              ),
              child: new Text(
                '${this.notifications[pos].length}',
                style: new TextStyle(
                  color: primaryColor(),
                  fontSize: 8,
                ),
                textAlign: TextAlign.center,
              ),
            ),
          )
        ],
      ),
      label: "Alerts"
    );
  }

  void disconnectCurrentSession() {
    var view = this.sessionViews.removeAt(this.pos);
    var username = this.tabs.removeAt(this.pos);
    // Also, delete any autologins. Only after can we then disconnect without getting a login auto triggered. They will need to login again to re-establish it
    AutoLogin.autologinAccounts?.removeWhere((key, value) => key == view.cnac.implicatedCid);
    SecureStorageHandler.deleteCredentialsFor(username)
    .then((value) => RustSubsystem.bridge!.executeCommand("disconnect ${view.cnac.username}"));
  }


  Optional<ClientNetworkAccount> getClientOfCurrentView() {
    if (this.sessionViews.isEmpty) {
      return Optional.empty();
    } else {
      return Optional.of(this.sessionViews[pos].cnac);
    }
  }
}

class RemoveNotification {
  final int idx;
  final u64 implicatedCid;

  const RemoveNotification(this.idx, this.implicatedCid);
}