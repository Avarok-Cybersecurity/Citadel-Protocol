import 'dart:ffi';
import 'dart:isolate';

import 'package:flutter/material.dart';
import 'package:flutterust/components/fade_indexed_stack.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/peer_list_handler.dart';
import 'package:flutterust/screens/session/session_subscreens/peer_list.dart';
import 'package:flutterust/themes/default.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/u64.dart';

import '../../main.dart';

class SessionView extends StatefulWidget {
  final u64 cid;
  final String username;
  ReceivePort recvPort;
  SendPort sendPort;

  SessionView(this.cid, this.username, Key key) : super(key: key) {
    this.recvPort = ReceivePort();
    this.sendPort = this.recvPort.sendPort;
  }

  @override
  State<StatefulWidget> createState() {
    return SessionViewInner();
  }
}

class SessionViewInner extends State<SessionView> {

  List<Widget> subscreens = [];
  int selectedIdx = 0;

  SessionViewInner();

  @override
  void initState() {
    super.initState();
    widget.recvPort = ReceivePort();
    widget.sendPort = widget.recvPort.sendPort;
    this.subscreens = this.generateInitStack();

    widget.recvPort.listen((message) {
      print("[SessionViewInner] recv signal");
      handle(message);
      setState(() {});
    });
  }

  void handle(dynamic dsr) {
    if (dsr is DomainSpecificResponse) {
      switch (dsr.getType()) {
        case DomainSpecificResponseType.PeerList:
          this.addView(PeerListView(Optional.of(dsr), widget.cid), PeerListView.IDX);
      }
    } else {
      print("Recv return to home signal");
      // for now, all other signals will imply home view
      this.selectedIdx = 0;
    }
  }

  void addView(Widget widget, int idx) {
    this.selectedIdx = idx;
    this.subscreens[idx] = widget;
  }

  List<Widget> generateInitStack() {
    return <Widget>[
      Container(
          padding: EdgeInsets.all(2),
          height: 120,
          child: GestureDetector(
              onTap: listPeers,
              child: Card(
                  child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: <Widget>[
                  Icon(MdiIcons.lan,
                      color: primaryColorValue, size: 100),
                  Expanded(
                      child: Container(
                          padding: EdgeInsets.all(5),
                          child: Column(
                              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                              children: <Widget>[
                                Text(
                                  "Discover Network Contacts",
                                  style: TextStyle(fontWeight: FontWeight.bold),
                                )
                              ])))
                ],
              )))),
      PeerListView(Optional.empty(), widget.cid)
    ];
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
        child: FadeIndexedStack(
      index: this.selectedIdx,
      children: this.subscreens,
    ));
  }

  void listPeers() async {
    print("Listing peers ...");
    String cmd = "switch " + widget.username + " peer list";
    (await RustSubsystem.bridge.executeCommand(cmd)).ifPresent((kResp) =>
        KernelResponseHandler.handleFirstCommand(kResp,
            handler: PeerListHandler(context, widget.sendPort)));
  }
}
