import 'package:flutter/material.dart';
import 'package:flutterust/components/default_widget.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/handlers/post_register_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/themes/default.dart';
import 'package:optional/optional.dart';
import 'package:satori_ffi_parser/types/dsr/peer_list.dart';
import 'package:satori_ffi_parser/types/u64.dart';
import 'package:satori_ffi_parser/utils.dart';

class PeerListView extends StatelessWidget {
  static const String routeName = "/peer_list_view";
  static const int IDX = 1;

  const PeerListView(this.args);

  final PeerListViewArguments args;

  List<TableRow> generateList() {
    if (args.resp.cids.isNotEmpty) {
      PeerListResponse resp = args.resp;
      List<TableRow> list = zip([resp.cids, resp.is_onlines]).map((data) {
        u64 cid = data[0];
        bool isOnline = data[1];
        Icon chosenIcon = isOnline ? createOnlineIcon() : createOfflineIcon();
        return TableRow(children: [
          Column(
            children: [
              Center(
                child: Padding(
                  padding: EdgeInsets.all(10),
                  child: Text(cid.toString()),
                ),
              )
            ],
          ),
          Column(
            children: [
              Center(
                  child: Padding(
                padding: EdgeInsets.all(10),
                child: chosenIcon,
              ))
            ],
          ),
          Column(
            children: [
              Center(
                  child: Padding(
                      padding: EdgeInsets.symmetric(vertical: 10),
                      child: IconButton(
                          onPressed: () {
                            onAddPressed(cid, args);
                          },
                          icon: createAddIcon())))
            ],
          )
        ]);
      }).toList();

      TableRow header = TableRow(children: [
        Column(
          children: [
            Center(
              child: Padding(
                padding: EdgeInsets.symmetric(vertical: 5),
                child: Icon(Icons.account_tree),
              ),
            )
          ],
        ),
        Column(
          children: [
            Center(
                child: Padding(
              padding: EdgeInsets.symmetric(vertical: 5),
              child: Icon(Icons.info),
            ))
          ],
        ),
        Center(
            child: Padding(
                padding: EdgeInsets.symmetric(vertical: 5),
                child: Icon(Icons.app_registration)))
      ]);

      list.insert(0, header);
      return list;
    }

    return [
      TableRow(children: [
        Column(
          children: [
            Center(
              child: Text("No peers on this network"),
            )
          ],
        )
      ])
    ];
  }

  static Icon createOnlineIcon() {
    return const Icon(Icons.wifi, color: Colors.green);
  }

  static Icon createOfflineIcon() {
    return const Icon(Icons.wifi_off, color: Colors.red);
  }

  Icon createAddIcon() {
    return const Icon(Icons.person_add_alt_1);
  }

  void onAddPressed(u64 cid, final PeerListViewArguments args) async {
    print("About to peer post-register to " + cid.toString());
    (await RustSubsystem.bridge.executeCommand("switch " +
            args.ctxCid.toString() +
            " peer post-register --fcm " +
            cid.toString()))
        .ifPresent((kResp) => KernelResponseHandler.handleFirstCommand(kResp,
            handler: PostRegisterHandler(cid), oneshot: false));
  }

  @override
  Widget build(BuildContext context) {
    return DefaultPageWidget(
        title: Text("Available Network Peers"),
      align: Alignment.topCenter,
      child: Table(
        border: TableBorder.all(color: primaryColor(), width: 1),
        children: generateList(),
      ),
    );
  }
}

class PeerListViewArguments {
  final PeerListResponse resp;
  final u64 ctxCid;

  const PeerListViewArguments(this.resp, this.ctxCid);
}
