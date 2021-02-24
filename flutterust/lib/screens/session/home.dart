
import 'dart:isolate';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/custom_tab_view.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/connect_response.dart';

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

  int initPosition = 0;

  SessionHomeScreenInner() {
    ReceivePort receivePort = ReceivePort("Session home screen");
    sendPort = receivePort.sendPort;

    receivePort.listen((message) {
      handle(message);
      setState(() {});
    });
  }

  /// handles either Connect or Disconnect dsr types, or, message types
  void handle(DomainSpecificResponse dsr) {
      switch (dsr.getType()) {
        case DomainSpecificResponseType.Connect:
          ConnectResponse conn = dsr;
          print("Adding session to sessions list for " + conn.implicated_cid.toString());
          tabs.add(conn.getAttachedUsername().orElse("UNATTACHED USERNAME"));
          sessionViews.add(Container(
            child: Center(
              child: Text("Implicated CID: " + conn.implicated_cid.toString()),
            ),
          ));

          print("Len: " + tabs.length.toString() + ", len: " + sessionViews.length.toString());
      }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: CustomTabView(
          initPosition: this.tabs.length != 0 ? this.tabs.length - 1 : 0,
          itemCount: this.tabs.length,
          tabBuilder: (context, index) => Tab(text: this.tabs[index]),
          pageBuilder: (context, index) => Center(child: this.sessionViews[index]),
          onPositionChange: (index){
            initPosition = index;
          },
          onScroll: (position) => print('$position'),
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          setState(() {
            //this.data.add('Page ${data.length}');
          });
        },
        child: Icon(Icons.add),
      ),
    );
  }

}