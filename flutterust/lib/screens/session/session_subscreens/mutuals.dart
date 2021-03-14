
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/default_widget.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/globals.dart';
import 'package:flutterust/screens/session/session_subscreens/mutual_peer.dart';
import 'package:flutterust/screens/session/session_subscreens/peer_list.dart';
import 'package:flutterust/utils.dart';
import 'package:quiver/iterables.dart';
import 'package:satori_ffi_parser/types/dsr/peer_mutuals.dart';
import 'package:satori_ffi_parser/types/u64.dart';

class MutualsView extends StatelessWidget {
  static const String routeName = "/mutuals_view";
  static const int IDX = 1;

  final PeerMutualsResponse response;
  final ClientNetworkAccount implicatedCnac;

  const MutualsView(this.response, this.implicatedCnac);

  @override
  Widget build(BuildContext context) {
    final title = Text("Verified Peers for ${this.implicatedCnac.username}");
    return DefaultPageWidget(
        title: title,
        child: generateWidget(context),
      align: Alignment.topCenter,
    );
  }

  Widget generateWidget(BuildContext ctx) {

      if (this.response.cids.isNotEmpty) {
        var resp = this.response;
        var image = CachedNetworkImageProvider(DEFAULT_AVATAR_IMAGE);
        List<ListTile> tiles = zip([resp.usernames, resp.is_onlines, resp.fcm_reachable, resp.cids]).map((e) {
          return ListTile(
            leading: CircleAvatar(
              backgroundImage: image,
            ),
            subtitle: e[1] || e[2] ? PeerListView.createOnlineIcon() : PeerListView.createOfflineIcon(),
            title: Text(e[0]),
            trailing: Icon(Icons.keyboard_arrow_right),
            onTap: () => onClick(ctx, e[0], e[3]),
          );
        }).toList(growable: false);

        return Container(
            child: ListView(
                shrinkWrap: true,
                physics: NeverScrollableScrollPhysics(),
                children: tiles
            )
        );
      }

    return Text("No mutually-consented peers. Find peers in 'Discover Network Contacts'");
  }

  void onClick(BuildContext ctx, String username, u64 cid) async {
    // navigator route to peer screen
    print("Click selected for $cid");
    // TODO: Get mutual from
    PeerNetworkAccount peerNac = (await PeerNetworkAccount.getPeerByCid(this.implicatedCnac.implicatedCid, cid)).value;
    Navigator.push(ctx, Utils.createDefaultRoute(MutualPeerScreen(this.implicatedCnac, peerNac)));
  }
}