import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutterust/components/cached_image.dart';
import 'package:flutterust/database/client_network_account.dart';
import 'package:flutterust/database/message.dart';
import 'package:flutterust/database/peer_network_account.dart';
import 'package:flutterust/handlers/deregister_handler.dart';
import 'package:flutterust/handlers/kernel_response_handler.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/screens/session/session_subscreens/messaging_screen.dart';
import 'package:flutterust/utils.dart';

class MutualPeerScreen extends StatelessWidget {
  static const String routeName = "/mutual_peer_screen";
  final ClientNetworkAccount implicatedUser;
  final PeerNetworkAccount peerNac;

  const MutualPeerScreen(this.implicatedUser, this.peerNac);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text("Mutual contact"),
      ),

      body: Container(
        child: SingleChildScrollView(
          child: Column(
            children: [
              Center(
                child: Padding(
                  padding: EdgeInsets.symmetric(vertical: 20),
                  child: Text(
                      this.peerNac.peerUsername,
                      textScaleFactor: 3,
                      style: TextStyle(
                          fontFamily: "Oxygen",
                          fontWeight: FontWeight.normal
                      )
                  ),
                ),
              ),

              Center(
                child: Container(
                  height: MediaQuery.of(context).size.height / 2,
                  decoration: BoxDecoration(
                    color: const Color(0xff7c94b6),
                    image: DecorationImage(
                      image: CachedNetworkImageProvider(peerNac.avatarUrl),
                      fit: BoxFit.cover
                    ),
                    border: Border.all(
                      color: Colors.black,
                      width: 2,
                    ),
                    borderRadius: BorderRadius.circular(12),

                  ),
                  padding: EdgeInsets.symmetric(vertical: 10),
                  margin: EdgeInsets.symmetric(horizontal: 10),
                )
              ),

              Container(
                padding: EdgeInsets.all(10),
                width: double.infinity,
                child: ElevatedButton.icon(
                  icon: Icon(Icons.message_outlined),
                  label: Text("Message"),
                  onPressed: () => openMessageScreen(context),
                ),
              )
            ],
          ),
        ),
      ),

      bottomSheet: Container(
        padding: EdgeInsets.all(10),
        width: double.infinity,
        child: ElevatedButton.icon(
          style: ButtonStyle(
              backgroundColor: MaterialStateProperty.all(Colors.red)
          ),
          icon: Icon(Icons.delete_outline),
          label: Text("Deregister"),
          onPressed: () => deregister(context),
        ),
      ),
    );
  }

  void openMessageScreen(BuildContext context) async {
    var screen = MessagingScreen(this.implicatedUser, this.peerNac);
    Navigator.push(context, Utils.createDefaultRoute(screen));
  }

  void deregister(BuildContext ctx) async {
    print("Will deregister ${this.peerNac.peerUsername} from ${this.implicatedUser.username}");
    // NOTE: Since the server tries to send via peer primary stream dereg occured, the FCM attempt to
    // perform a dereg returns an error since it can't find a peer session crypto container. As such,
    // as it stands, there is redundancy. Still, we should disable server-> primary stream dereg communication
    // temporarily to check to see if it works using the BG processor. Plus, this will allow us to see how
    // endpoint crypto works using the FCM ratchets for once. Because once that is proven to work, then getting
    // p2p messages to work is very close to happening
    (await RustSubsystem.bridge.executeCommand("switch ${this.implicatedUser.implicatedCid} peer deregister ${this.peerNac.peerUsername} --fcm"))
    .ifPresent((kResp) => KernelResponseHandler.handleFirstCommand(kResp, handler: DeregisterHandler(), oneshot: false));
    Navigator.of(ctx).pop();
  }

}