import 'dart:ffi';
import 'dart:isolate';

import 'package:flutter/material.dart';
import 'package:flutterust/components/fade_indexed_stack.dart';
import 'package:flutterust/components/nest_safe_gesture_detector.dart';
import 'package:flutterust/components/shadowed_container.dart';
import 'package:flutterust/database_handler.dart';
import 'package:flutterust/handlers/PeerMutualsHandler.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/peer_list_handler.dart';
import 'package:flutterust/screens/session/session_subscreens/mutuals.dart';
import 'package:flutterust/screens/session/session_subscreens/peer_list.dart';
import 'package:flutterust/themes/default.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';

import '../../main.dart';

class SessionView extends StatefulWidget {
  final ClientNetworkAccount cnac;
  ReceivePort recvPort;
  SendPort sendPort;

  SessionView(this.cnac, Key key) : super(key: key) {
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
          this.addView(
              PeerListView(Optional.of(dsr), widget.cnac.implicatedCid),
              PeerListView.IDX);
          break;

        case DomainSpecificResponseType.PeerMutuals:
          this.addView(
              MutualsView(Optional.of(dsr)),
              MutualsView.IDX);
          break;
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
          padding: EdgeInsets.all(10),
            child: SingleChildScrollView(
             child: Container(
              child: ListView(
                shrinkWrap: true,
                physics: NeverScrollableScrollPhysics(),
                  children: [
                    ShadowContainer(
                      padding: EdgeInsets.all(2),
                      height: 120,
                      child: ListTile(
                        leading: Icon(MdiIcons.lan, color: primaryColorValue, size: 100),
                        title: Text(
                          "Discover Network Contacts",
                          style: TextStyle(fontWeight: FontWeight.bold),
                        ),

                        onTap: listPeers,
                      ),
                    ),

                    ShadowContainer(
                      padding: EdgeInsets.all(2),
                      height: 120,
                      child: ListTile(
                        leading: Icon(MdiIcons.accountMultipleCheck, color: primaryColorValue, size: 100),
                        title: Text(
                          "Verified Contacts",
                          style: TextStyle(fontWeight: FontWeight.bold),
                        ),

                        onTap: listMutuals,

                      ),
                    )
                  ]
              )
            ),
          ),
        ),
      PeerListView(Optional.empty(), widget.cnac.implicatedCid),
      MutualsView(Optional.empty())
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
    String cmd = "switch " + widget.cnac.username + " peer list";
    (await RustSubsystem.bridge.executeCommand(cmd)).ifPresent((kResp) =>
        KernelResponseHandler.handleFirstCommand(kResp,
            handler: PeerListHandler(context, widget.sendPort)));
  }

  void listMutuals() async {
    print("Listing mutuals ...");
    String cmd = "switch " + widget.cnac.username + " peer mutuals";
    (await RustSubsystem.bridge.executeCommand(cmd)).ifPresent((kResp) =>
        KernelResponseHandler.handleFirstCommand(kResp,
            handler: PeerMutualsHandler(context, widget.sendPort)));
  }
}
