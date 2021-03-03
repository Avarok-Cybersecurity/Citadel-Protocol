
import 'package:flutter/material.dart';
import 'package:flutterust/screens/session/session_subscreens/peer_list.dart';
import 'package:optional/optional.dart';
import 'package:quiver/iterables.dart';
import 'package:satori_ffi_parser/types/dsr/peer_mutuals.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class MutualsView extends StatelessWidget {
  final Optional<PeerMutualsResponse> response;
  static const int IDX = 2;

  MutualsView(this.response);

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Container(
        padding: EdgeInsets.all(10),
        child: SingleChildScrollView(
          child: Container(
              child: ListView(
                  shrinkWrap: true,
                  physics: NeverScrollableScrollPhysics(),
                  children: generateList()
              )
          ),
        ),
      ),
    );
  }

  List<Widget> generateList() {
    if (this.response.isPresent) {
      var resp = this.response.value;
      const image = NetworkImage('https://flutter.github.io/assets-for-api-docs/assets/widgets/owl.jpg');
      return zip([resp.usernames, resp.is_onlines, resp.fcm_reachable, resp.cids]).map((e) {
        return ListTile(
          leading: CircleAvatar(
            backgroundImage: image,
          ),
          subtitle: e[1] || e[2] ? PeerListView.createOnlineIcon() : PeerListView.createOfflineIcon(),
          title: Text(e[0]),
          trailing: Icon(Icons.keyboard_arrow_right),
          onTap: () { onClick(e[0], e[3]); },
        );
      }).toList(growable: false);
    } else {
      return [];
    }
  }

  void onClick(String username, u64 cid) {
    print("Click selected for $cid");
  }
}