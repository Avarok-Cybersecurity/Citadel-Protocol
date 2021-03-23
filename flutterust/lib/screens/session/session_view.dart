import 'dart:async';

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/shadowed_container.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/handlers/peer_mutuals_handler.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/peer_list_handler.dart';
import 'package:flutterust/screens/session/session_subscreens/mutuals.dart';
import 'package:flutterust/screens/session/session_subscreens/peer_list.dart';
import 'package:flutterust/themes/default.dart';
import 'package:flutterust/utils.dart';
import 'package:material_design_icons_flutter/material_design_icons_flutter.dart';
import 'package:satori_ffi_parser/types/domain_specific_response.dart';
import 'package:satori_ffi_parser/types/domain_specific_response_type.dart';
import 'package:satori_ffi_parser/types/dsr/peer_list.dart';
import 'package:satori_ffi_parser/types/dsr/peer_mutuals.dart';

import '../../main.dart';

class SessionView extends StatefulWidget {
  final ClientNetworkAccount cnac;
  final StreamController streamController;

  SessionView(this.cnac, Key? key) : this.streamController = StreamController(), super(key: key);

  @override
  State<StatefulWidget> createState() {
    return SessionViewInner();
  }
}

class SessionViewInner extends State<SessionView> {
  late final StreamSubscription listener;

  @override
  void initState() {
    super.initState();

    this.listener = this.widget.streamController.stream.listen((dsr) {
      print("Received DSR");
      this.handle(dsr);
      setState(() {});
    });
  }

  @override
  void dispose() {
    super.dispose();
    this.listener.cancel();
  }

  void handle(dynamic dsr) {
    if (dsr is DomainSpecificResponse) {
      switch (dsr.getType()) {
        case DomainSpecificResponseType.PeerList:
          final args = PeerListViewArguments(dsr as PeerListResponse, widget.cnac.implicatedCid);
          Navigator.push(context, Utils.createDefaultRoute(PeerListView(args)));
          break;

        case DomainSpecificResponseType.PeerMutuals:
          Navigator.push(context, Utils.createDefaultRoute(MutualsView(dsr as PeerMutualsResponse, widget.cnac)));
          break;

        default: break;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
        child: Container(
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
        )
    );
  }

  void listPeers() async {
    print("Listing peers ...");
    String cmd = "switch " + widget.cnac.username + " peer list";
    (await RustSubsystem.bridge!.executeCommand(cmd)).ifPresent((kResp) =>
        KernelResponseHandler.handleFirstCommand(kResp,
            handler: PeerListHandler(context, widget.streamController.sink)));
  }

  void listMutuals() async {
    print("Listing mutuals ...");
    String cmd = "switch " + widget.cnac.username + " peer mutuals";
    (await RustSubsystem.bridge!.executeCommand(cmd)).ifPresent((kResp) =>
        KernelResponseHandler.handleFirstCommand(kResp,
            handler: PeerMutualsHandler(context, widget.streamController.sink)));
  }
}
