
import 'dart:isolate';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutterust/components/custom_tab_view.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/screens/session/session_view.dart';
import 'package:quiver/iterables.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';
import 'package:satori_ffi_parser/types/dsr/get_active_sessions.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class SessionHomeScreen extends StatefulWidget {
  static const IDX = 2;

  SessionHomeScreen({Key key}) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return SessionHomeScreenInner();
  }
}

class SessionHomeScreenInner extends State<SessionHomeScreen> {
  static SendPort sendPort;

  List<String> tabs = [];
  List<Widget> sessionViews = [];

  int pos = 0;

  SessionHomeScreenInner() {
    ReceivePort receivePort = ReceivePort("Session home screen");
    sendPort = receivePort.sendPort;

    receivePort.listen((message) {
      handle(message);
      setState(() {});
    });
  }

  @override
  void initState() {
    super.initState();
    this.onStart();
  }

  /// initState cannot be async, so the function is moved to a separate fn
  void onStart() async {
    (await RustSubsystem.bridge.executeCommand("list-sessions"))
        .ifPresent((kResp) { kResp.getDSR().ifPresent((dsr) { sendPort.send(dsr); }); });
  }

  /// handles either Connect or Disconnect dsr types, or, message types
  void handle(DomainSpecificResponse dsr) {
    print("[SessionHomeScreen] recv'd dsr " + dsr.getType().toString());
      switch (dsr.getType()) {
        case DomainSpecificResponseType.Connect:
          ConnectResponse conn = dsr;
          print("Adding session to sessions list for " + conn.implicated_cid.toString());
          final String username = conn.getAttachedUsername().orElse("UNATTACHED USERNAME");
          tabs.add(username);

          sessionViews.add(SessionView(conn.implicated_cid, username, widget.key));

          print("Len: " + tabs.length.toString() + ", len: " + sessionViews.length.toString());
          break;

        case DomainSpecificResponseType.GetActiveSessions:
          GetSessionsResponse resp = dsr;
          if (resp.cids.length != 0) {
            List<List<Object>> vals = zip(([resp.cids, resp.usernames])).where((data) {
              u64 cid = data[0];
              return this.sessionViews.indexWhere((widget) => (widget as SessionView).cid == cid) == -1;
            }).toList(growable: false);

            print("Found " + vals.length.toString() + " sessions unaccounted for in the GUI");
            vals.forEach((element) {
              tabs.add(element[1]);
              sessionViews.add(SessionView(element[0], element[1], widget.key));
            });

            print("Len: " + tabs.length.toString() + ", len: " + sessionViews.length.toString());
          } else {
            this.sessionViews.clear();
            this.pos = 0;
          }
          break;
      }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: CustomTabView(
          initPosition: this.tabs.length != 0 ? this.pos : 0,
          itemCount: this.tabs.length,
          tabBuilder: (context, index) => Tab(text: this.tabs[index]),
          pageBuilder: (context, index) => Center(child: this.sessionViews[index]),
          onPositionChange: (index){
              print("Pos changing: " + index.toString());
              pos = index;
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          setState(() {
            print("FAB clicked");
            if (this.sessionViews.length != 0) {
              SessionView sView = this.sessionViews[pos];
              sView.sendPort.send(0);
            }
          });
        },
        child: Icon(Icons.home),
      ),
    );
  }

}